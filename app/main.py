"""
Google Cloud Armor Defensive Security Study Demo Service (cloud-armor-study-01)

Safe, non-weaponized diagnostic web service deployed on Cloud Run (asia-southeast2)
with ingress restricted to `internal-and-cloud-load-balancing` behind the global
External Application Load Balancer (`gcp2-xlb`) at `https://gcp2demo01.iphamsterviel.org`.

Endpoints:
  - GET  /                   : Public baseline status & architecture overview (JSON)
  - GET  /healthz            : Health check endpoint (JSON)
  - GET  /admin/diagnostics  : Mock administrative diagnostics route (illustrates why
                               Cloud Armor Custom CEL route/header enforcement is needed)
  - GET  /api/inspect        : Safe header & query parameter echo endpoint (illustrates
                               L7 inspection for custom markers and OWASP CRS rules)
  - POST /api/inspect        : Safe JSON body + header/query echo endpoint
  - GET  /api/ping           : Lightweight unthrottled endpoint (illustrates Cloud Armor
                               rate-limiting / throttling at the edge)
"""

from datetime import datetime, timezone
import os
from typing import Any, Dict
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Cloud Armor Defensive Security Study Demo",
    description=(
        "Safe diagnostic web service demonstrating Layer-7 defense-in-depth with "
        "Cloud Run (restricted ingress), Global External Application Load Balancing "
        "(gcp2-xlb), and Google Cloud Armor."
    ),
    version="1.0.0",
)

SERVICE_NAME = os.environ.get("K_SERVICE", "cloud-armor-demo-service")
SERVICE_REVISION = os.environ.get("K_REVISION", "local-dev")
GCP_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "gcp-demo-02-307713")
GCP_REGION = os.environ.get("CLOUD_RUN_REGION", "asia-southeast2")


def _extract_request_context(request: Request) -> Dict[str, Any]:
    """Extracts safe, non-sensitive networking and proxy headers from the request."""
    headers = request.headers
    xff = headers.get("x-forwarded-for", "")
    client_ip = xff.split(",")[0].strip() if xff else (
        request.client.host if request.client else "unknown"
    )
    return {
        "host": headers.get("host", ""),
        "path": request.url.path,
        "query_string": request.url.query,
        "method": request.method,
        "client_ip": client_ip,
        "x_forwarded_for": xff,
        "x_forwarded_proto": headers.get("x-forwarded-proto", ""),
        "via": headers.get("via", ""),
        "x_cloud_trace_context": headers.get("x-cloud-trace-context", ""),
        "routed_via_google_xlb": "google" in headers.get("via", "").lower()
        or bool(headers.get("x-cloud-trace-context")),
    }


@app.get("/")
async def root_baseline(request: Request) -> JSONResponse:
    """Public baseline endpoint returning service metadata and available study routes."""
    return JSONResponse(
        status_code=200,
        content={
            "service": SERVICE_NAME,
            "revision": SERVICE_REVISION,
            "project": GCP_PROJECT,
            "region": GCP_REGION,
            "status": "ok",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "message": (
                "Baseline request succeeded through External Application Load Balancer "
                "(gcp2-xlb) to Cloud Run (asia-southeast2)."
            ),
            "request_context": _extract_request_context(request),
            "study_endpoints": {
                "/": "Public baseline endpoint (allowed pre-Armor and post-Armor)",
                "/healthz": "Health check endpoint",
                "/admin/diagnostics": (
                    "Mock admin diagnostics route. Pre-Armor: exposed (HTTP 200) without auth. "
                    "Post-Armor: blocked at edge (HTTP 403) unless header "
                    "'X-Admin-Token: study-secret-2026' is provided."
                ),
                "/api/inspect": (
                    "Header & query inspection echo endpoint. Pre-Armor: allows all markers. "
                    "Post-Armor: Cloud Armor blocks test marker ('X-Policy-Test: block-me' or "
                    "'?policy_test=block') and OWASP CRS WAF signatures at the edge (HTTP 403)."
                ),
                "/api/ping": (
                    "Rate-limit test endpoint. Pre-Armor: unthrottled (bursts return HTTP 200). "
                    "Post-Armor: Cloud Armor throttles bursts exceeding 10 req/60s per IP "
                    "(HTTP 429 Too Many Requests)."
                ),
            },
        },
    )


@app.get("/healthz")
async def healthz() -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": SERVICE_NAME,
            "revision": SERVICE_REVISION,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.get("/admin/diagnostics")
async def admin_diagnostics(request: Request) -> JSONResponse:
    """
    Unprotected mock admin/diagnostics route.
    Simulates an internal diagnostic route left exposed without application-level auth,
    showing why a Cloud Armor Custom CEL rule at the load balancer edge is critical.
    """
    admin_token = request.headers.get("x-admin-token")
    has_valid_token = admin_token == "study-secret-2026"
    return JSONResponse(
        status_code=200,
        content={
            "endpoint": "/admin/diagnostics",
            "service": SERVICE_NAME,
            "revision": SERVICE_REVISION,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "admin_token_present": bool(admin_token),
            "admin_token_valid": has_valid_token,
            "security_observation": (
                "AUTHORIZED: Valid X-Admin-Token header verified."
                if has_valid_token
                else (
                    "EXPOSED_WITHOUT_CLOUD_ARMOR: This mock admin endpoint returned HTTP 200 "
                    "even though no valid X-Admin-Token header was supplied! Attaching the "
                    "Cloud Armor Custom CEL rule (Priority 1000) blocks unauthorized requests "
                    "at the global XLB edge with HTTP 403 Forbidden."
                )
            ),
            "mock_diagnostics": {
                "cloud_run_ingress_mode": "internal-and-cloud-load-balancing",
                "load_balancer": "gcp2-xlb (34.49.218.84)",
                "domain": "gcp2demo01.iphamsterviel.org",
                "backend_region": GCP_REGION,
                "mock_feature_flags": {
                    "verbose_telemetry": True,
                    "debug_trace_export": True,
                    "maintenance_mode": False,
                },
            },
            "request_context": _extract_request_context(request),
        },
    )


@app.api_route("/api/inspect", methods=["GET", "POST"])
async def api_inspect(request: Request) -> JSONResponse:
    """
    Safe header, query parameter, and JSON body echo endpoint.
    Performs zero code execution or database queries—only echoes sanitized metadata
    so we can compare pre-Armor vs. post-Armor filtering behavior.
    """
    body_preview: Any = None
    if request.method == "POST":
        try:
            body_preview = await request.json()
        except Exception:
            raw_bytes = await request.body()
            body_preview = raw_bytes[:512].decode("utf-8", errors="replace")

    policy_test_header = request.headers.get("x-policy-test", "")
    policy_test_query = request.query_params.get("policy_test", "")
    marker_detected = (
        policy_test_header == "block-me" or policy_test_query == "block"
    )

    return JSONResponse(
        status_code=200,
        content={
            "endpoint": "/api/inspect",
            "service": SERVICE_NAME,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "policy_marker_detected_at_origin": marker_detected,
            "security_observation": (
                "UNFILTERED_AT_EDGE: Request carrying policy test marker reached the Cloud Run "
                "origin because Cloud Armor is not yet attached (or rule is disabled)."
                if marker_detected
                else "CLEAN_REQUEST: No block marker detected in headers or query parameters."
            ),
            "inspected_parameters": {
                "query_params": dict(request.query_params),
                "selected_headers": {
                    "user-agent": request.headers.get("user-agent", ""),
                    "x-policy-test": policy_test_header,
                    "x-admin-token": (
                        "***present***"
                        if "x-admin-token" in request.headers
                        else "absent"
                    ),
                    "content-type": request.headers.get("content-type", ""),
                },
                "body_preview": body_preview,
            },
            "request_context": _extract_request_context(request),
        },
    )


@app.get("/api/ping")
async def api_ping(request: Request) -> JSONResponse:
    """
    Lightweight endpoint used to test Cloud Armor rate limiting (throttling).
    At the application layer this route has no rate limiter; Cloud Armor Priority 3000
    throttles bursts exceeding 10 requests per 60 seconds per client IP with HTTP 429.
    """
    return JSONResponse(
        status_code=200,
        content={
            "pong": True,
            "endpoint": "/api/ping",
            "request_id": str(uuid.uuid4()),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "client_ip": _extract_request_context(request)["client_ip"],
            "note": (
                "Unthrottled at application layer; protected at L7 edge by Cloud Armor "
                "rate-limit rule (10 req / 60s per client IP -> HTTP 429)."
            ),
        },
    )
