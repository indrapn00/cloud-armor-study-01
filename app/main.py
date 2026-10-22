"""
Google Cloud Armor Defensive Security Study Demo Service (cloud-armor-study-01)

Interactive Web Browser Study Portal + Diagnostic API deployed on Cloud Run
(asia-southeast2) with ingress restricted to `internal-and-cloud-load-balancing`
behind the global External Application Load Balancer (`gcp2-xlb`) at
`https://gcp2demo01.iphamsterviel.org`.

Browser & API Endpoints:
  - GET  /                   : Interactive Web Browser Study Lab (HTML UI with Login Tab,
                               Search/XSS Tab, Document/LFI/RCE Tab, Admin/CEL Tab, &
                               Rate-Limit Burst Tester) — or JSON if Accept: application/json
  - GET/POST /login          : Interactive Login handler backed by an ephemeral in-memory
                               SQLite table to demonstrate SQLi authentication bypass into
                               the Next Page (/portal/dashboard) Pre-Armor vs. HTTP 403 block
                               at the edge Post-Armor
  - GET  /portal/dashboard   : The "Next Page" internal portal view reached after Login
  - GET  /search             : Interactive Search page for testing OWASP XSS WAF filtering
  - GET  /viewer             : Interactive Mock Document/Ping viewer for LFI/RCE WAF rules
  - GET  /api/status         : JSON baseline status & architecture overview
  - GET  /healthz            : Health check endpoint (JSON)
  - GET  /admin/diagnostics  : Mock administrative diagnostics route (Priority 1000 CEL)
  - GET/POST /api/inspect    : Header & query parameter echo endpoint (Priority 1100 CEL)
  - GET  /api/ping           : Lightweight unthrottled endpoint (Priority 3000 Rate Limit)
"""

from datetime import datetime, timezone
import html
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(
    title="Cloud Armor Interactive Web Security Study Portal",
    description=(
        "Interactive browser study portal & diagnostic service demonstrating Layer-7 "
        "defense-in-depth with Cloud Run (restricted ingress), Global External Application "
        "Load Balancing (gcp2-xlb), and Google Cloud Armor."
    ),
    version="2.0.0",
)

SERVICE_NAME = os.environ.get("K_SERVICE", "cloud-armor-demo-service")
SERVICE_REVISION = os.environ.get("K_REVISION", "local-dev")
GCP_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "gcp-demo-02-307713")
GCP_REGION = os.environ.get("CLOUD_RUN_REGION", "asia-southeast2")

MOCK_DOCUMENTS: Dict[str, str] = {
    "architecture-overview.txt": (
        "Google Cloud Armor Study Architecture (gcp-demo-02-307713)\n"
        "- Frontend: Global External Application Load Balancer (gcp2-xlb / 34.49.218.84)\n"
        "- Hostname: gcp2demo01.iphamsterviel.org\n"
        "- Edge Security Policy: cloud-armor-study-policy-01\n"
        "- Origin: Cloud Run (cloud-armor-demo-service) in asia-southeast2\n"
        "- Origin Ingress: internal-and-cloud-load-balancing"
    ),
    "waf-policy-notes.txt": (
        "Active Cloud Armor Rules on cloud-armor-study-policy-01:\n"
        "- Priority 1000: Custom CEL protecting /admin/diagnostics (requires X-Admin-Token)\n"
        "- Priority 1100: Custom CEL blocking X-Policy-Test: block-me and ?policy_test=block\n"
        "- Priority 2000: OWASP CRS v3.3 sqli-v33-stable & xss-v33-stable (Sensitivity 1)\n"
        "- Priority 2100: OWASP CRS v3.3 lfi-v33-stable, rce-v33-stable, scannerdetection-v33-stable\n"
        "- Priority 3000: Rate Limit THROTTLE on /api/ping (10 req / 60s per client IP -> HTTP 429)"
    ),
}


def _extract_request_context(request: Request) -> Dict[str, Any]:
    """Extracts networking and load-balancer headers from the incoming request."""
    headers = request.headers
    xff = headers.get("x-forwarded-for", "")
    client_ip = (
        xff.split(",")[0].strip()
        if xff
        else (request.client.host if request.client else "unknown")
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


def _evaluate_study_login_query(
    username: str, password: str
) -> Tuple[str, List[Dict[str, Any]], Optional[str]]:
    """
    Creates an isolated, ephemeral in-memory SQLite database containing 4 fictional
    study user rows and executes an intentionally unparameterized SELECT statement
    so the user can observe SQLi authentication bypass in the browser when Cloud Armor
    is detached vs. edge blocking (HTTP 403) when Cloud Armor is attached.
    """
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE study_users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT,
            clearance TEXT,
            vault_note TEXT
        )
        """
    )
    seed_rows = [
        (
            1,
            "admin",
            "Sup3rS3cr3tAdmin!2026",
            "Global Security Administrator",
            "LEVEL_5_EXECUTIVE_VAULT",
            "Vault Secret: CLOUD-ARMOR-EXECUTIVE-KEY-9941 (Internal Only)",
        ),
        (
            2,
            "indrapn",
            "ArgolisStudy!2026",
            "Cloud Network Security Architect",
            "LEVEL_4_ARCHITECT",
            "Argolis Project: gcp-demo-02-307713 | XLB: gcp2-xlb (34.49.218.84)",
        ),
        (
            3,
            "demo_user",
            "CloudArmor2026!",
            "Standard Study Portal Member",
            "LEVEL_1_STANDARD",
            "Standard portal access verified through gcp2-xlb.",
        ),
        (
            4,
            "auditor",
            "AuditReview#2026",
            "OWASP Compliance Auditor",
            "LEVEL_3_READONLY",
            "Audit Target: OWASP CRS v3.3 Preconfigured WAF Rules",
        ),
    ]
    cursor.executemany(
        "INSERT INTO study_users VALUES (?, ?, ?, ?, ?, ?)", seed_rows
    )

    raw_sql = (
        "SELECT id, username, role, clearance, vault_note "
        f"FROM study_users WHERE username = '{username}' AND password = '{password}';"
    )

    matched_rows: List[Dict[str, Any]] = []
    sql_error: Optional[str] = None
    try:
        for row in cursor.execute(raw_sql).fetchall():
            matched_rows.append(
                {
                    "id": row[0],
                    "username": row[1],
                    "role": row[2],
                    "clearance": row[3],
                    "vault_note": row[4],
                }
            )
    except Exception as exc:
        sql_error = str(exc)
    finally:
        conn.close()

    return raw_sql, matched_rows, sql_error


SHARED_CSS = """
:root {
  --bg-page: #f4f6f9;
  --bg-surface: #ffffff;
  --bg-subtle: #eef2f7;
  --bg-code: #0f172a;
  --text-main: #0f172a;
  --text-muted: #475569;
  --border-color: #cbd5e1;
  --brand-blue: #0b57d0;
  --brand-blue-hover: #0842a0;
  --brand-blue-soft: #e8f0fe;
  --danger-red: #b3261e;
  --danger-bg: #fce8e6;
  --danger-border: #f2b8b5;
  --success-green: #137333;
  --success-bg: #e6f4ea;
  --success-border: #a8dab5;
  --warn-amber: #b06000;
  --warn-bg: #fef7e0;
  --warn-border: #fde293;
  --radius-md: 10px;
  --radius-sm: 6px;
  --shadow-sm: 0 1px 3px rgba(15, 23, 42, 0.08);
  --shadow-md: 0 4px 14px rgba(15, 23, 42, 0.08);
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background-color: var(--bg-page);
  color: var(--text-main);
  line-height: 1.55;
}
header.topbar {
  background: #ffffff;
  border-bottom: 1px solid var(--border-color);
  padding: 16px 24px;
  position: sticky;
  top: 0;
  z-index: 20;
  box-shadow: var(--shadow-sm);
}
.topbar-inner {
  max-width: 1180px;
  margin: 0 auto;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.brand-title {
  display: flex;
  align-items: center;
  gap: 12px;
}
.brand-title h1 {
  font-size: 1.2rem;
  font-weight: 700;
  margin: 0;
  letter-spacing: -0.01em;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.78rem;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 999px;
}
.badge-blue {
  background: var(--brand-blue-soft);
  color: var(--brand-blue);
}
.badge-green {
  background: var(--success-bg);
  color: var(--success-green);
  border: 1px solid var(--success-border);
}
.badge-red {
  background: var(--danger-bg);
  color: var(--danger-red);
  border: 1px solid var(--danger-border);
}
.badge-amber {
  background: var(--warn-bg);
  color: var(--warn-amber);
  border: 1px solid var(--warn-border);
}
.container {
  max-width: 1180px;
  margin: 24px auto 56px;
  padding: 0 20px;
}
.arch-bar {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 14px 18px;
  margin-bottom: 20px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  box-shadow: var(--shadow-sm);
  font-size: 0.88rem;
}
.arch-chain {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.82rem;
}
.arch-node {
  background: var(--bg-subtle);
  border: 1px solid var(--border-color);
  padding: 4px 10px;
  border-radius: var(--radius-sm);
}
.tabs-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 18px;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 10px;
}
.tab-btn {
  background: var(--bg-surface);
  color: var(--text-muted);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 10px 16px;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}
.tab-btn:hover {
  border-color: var(--brand-blue);
  color: var(--brand-blue);
}
.tab-btn.active {
  background: var(--brand-blue);
  color: #ffffff;
  border-color: var(--brand-blue);
}
.tab-panel {
  display: none;
}
.tab-panel.active {
  display: block;
}
.grid-2 {
  display: grid;
  grid-template-columns: 1.15fr 0.85fr;
  gap: 20px;
}
@media (max-width: 900px) {
  .grid-2 {
    grid-template-columns: 1fr;
  }
}
.card {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 22px;
  box-shadow: var(--shadow-sm);
}
.card h2 {
  margin-top: 0;
  margin-bottom: 8px;
  font-size: 1.15rem;
}
.card h3 {
  margin-top: 0;
  margin-bottom: 10px;
  font-size: 1rem;
}
.subtext {
  color: var(--text-muted);
  font-size: 0.92rem;
  margin-top: 0;
  margin-bottom: 16px;
}
.form-group {
  margin-bottom: 14px;
}
.form-group label {
  display: block;
  font-size: 0.86rem;
  font-weight: 600;
  margin-bottom: 6px;
}
.form-control {
  width: 100%;
  padding: 10px 12px;
  font-size: 0.95rem;
  font-family: 'JetBrains Mono', monospace;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  background: #ffffff;
  color: var(--text-main);
}
.form-control:focus {
  outline: 2px solid var(--brand-blue);
  border-color: var(--brand-blue);
}
.preset-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 10px 16px;
  font-size: 0.9rem;
  font-weight: 600;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.15s ease;
}
.btn-primary {
  background: var(--brand-blue);
  color: #ffffff;
}
.btn-primary:hover {
  background: var(--brand-blue-hover);
}
.btn-outline {
  background: #ffffff;
  border-color: var(--border-color);
  color: var(--text-main);
}
.btn-outline:hover {
  background: var(--bg-subtle);
  border-color: #94a3b8;
}
.btn-danger-soft {
  background: var(--danger-bg);
  border-color: var(--danger-border);
  color: var(--danger-red);
}
.btn-danger-soft:hover {
  background: #f9d2ce;
}
.btn-success-soft {
  background: var(--success-bg);
  border-color: var(--success-border);
  color: var(--success-green);
}
.btn-sm {
  padding: 6px 12px;
  font-size: 0.8rem;
}
.code-box {
  background: var(--bg-code);
  color: #e2e8f0;
  padding: 14px 16px;
  border-radius: var(--radius-sm);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.82rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  margin: 10px 0;
}
.alert-box {
  padding: 14px 16px;
  border-radius: var(--radius-sm);
  margin-bottom: 16px;
  font-size: 0.9rem;
}
.alert-danger {
  background: var(--danger-bg);
  border: 1px solid var(--danger-border);
  color: var(--danger-red);
}
.alert-success {
  background: var(--success-bg);
  border: 1px solid var(--success-border);
  color: var(--success-green);
}
.alert-warn {
  background: var(--warn-bg);
  border: 1px solid var(--warn-border);
  color: var(--warn-amber);
}
table.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.86rem;
  margin-top: 10px;
}
table.data-table th,
table.data-table td {
  border: 1px solid var(--border-color);
  padding: 9px 12px;
  text-align: left;
}
table.data-table th {
  background: var(--bg-subtle);
  font-weight: 600;
}
.burst-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
  gap: 8px;
  margin-top: 14px;
}
.burst-tile {
  padding: 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
  background: var(--bg-subtle);
  text-align: center;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
}
.burst-tile.ok {
  background: var(--success-bg);
  border-color: var(--success-border);
  color: var(--success-green);
}
.burst-tile.throttled {
  background: var(--danger-bg);
  border-color: var(--danger-border);
  color: var(--danger-red);
}
"""


def _render_study_portal_html(request: Request) -> str:
    ctx = _extract_request_context(request)
    client_ip = html.escape(ctx["client_ip"])
    host = html.escape(ctx["host"] or "gcp2demo01.iphamsterviel.org")
    via_xlb = "Yes (gcp2-xlb)" if ctx["routed_via_google_xlb"] else "Direct / Local"

    template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Google Cloud Armor — Interactive Web Security Study Lab</title>
  <meta name="description" content="Interactive browser testbed for studying Google Cloud Armor OWASP CRS WAF rules, SQLi login bypass, XSS, LFI/RCE, Custom CEL rules, and Rate Limiting on gcp2-xlb." />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>__SHARED_CSS__</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand-title">
        <span class="badge badge-blue">🛡️ Cloud Armor Study Lab</span>
        <h1>Interactive Vulnerability &amp; WAF Verification Portal</h1>
      </div>
      <div>
        <span class="badge badge-green">Origin: __SERVICE_NAME__ (__GCP_REGION__)</span>
        <span class="badge badge-blue">Client IP: __CLIENT_IP__</span>
      </div>
    </div>
  </header>

  <main class="container">
    <section class="arch-bar" aria-label="Request Routing Path">
      <div>
        <strong>Active Request Path:</strong>
        <span class="arch-chain">
          <span class="arch-node">Browser (__CLIENT_IP__)</span> &rarr;
          <span class="arch-node">gcp2-xlb (__HOST__)</span> &rarr;
          <span class="arch-node">Cloud Armor (cloud-armor-study-policy-01)</span> &rarr;
          <span class="arch-node">Serverless NEG</span> &rarr;
          <span class="arch-node">Cloud Run (__VIA_XLB__)</span>
        </span>
      </div>
      <div>
        <a class="btn btn-outline btn-sm" href="/api/status" target="_blank" id="link-raw-json">View Raw JSON Status</a>
      </div>
    </section>

    <nav class="tabs-nav" role="tablist" aria-label="Vulnerability Study Tabs">
      <button class="tab-btn active" id="tab-btn-sqli" onclick="switchTab('sqli')" role="tab">1. Login Portal (SQLi Auth Bypass)</button>
      <button class="tab-btn" id="tab-btn-xss" onclick="switchTab('xss')" role="tab">2. Search Wall (XSS Filter)</button>
      <button class="tab-btn" id="tab-btn-lfirce" onclick="switchTab('lfirce')" role="tab">3. File &amp; Ping Tool (LFI &amp; RCE)</button>
      <button class="tab-btn" id="tab-btn-cel" onclick="switchTab('cel')" role="tab">4. Admin &amp; Custom CEL Rules</button>
      <button class="tab-btn" id="tab-btn-rate" onclick="switchTab('rate')" role="tab">5. Rate-Limit Burst Tester</button>
    </nav>

    <!-- TAB 1: SQL INJECTION LOGIN PORTAL -->
    <section class="tab-panel active" id="panel-sqli" role="tabpanel">
      <div class="grid-2">
        <div class="card">
          <h2>Executive Vault Sign-In (SQL Injection Study Tab)</h2>
          <p class="subtext">
            This login form authenticates against an in-memory SQLite table using an unparameterized SQL query.
            Test how an SQL Injection payload logs directly into the <strong>Next Page (<code>/portal/dashboard</code>)</strong> when Cloud Armor is detached, and how <strong>Cloud Armor Priority 2000 (<code>sqli-v33-stable</code>)</strong> blocks it at the edge with <code>HTTP 403 Forbidden</code> when attached.
          </p>

          <div class="preset-bar">
            <button type="button" class="btn btn-success-soft btn-sm" id="btn-preset-valid" onclick="fillLogin('demo_user', 'CloudArmor2026!')">
              ✅ Fill Valid User (Allowed Pre &amp; Post Armor)
            </button>
            <button type="button" class="btn btn-danger-soft btn-sm" id="btn-preset-sqli-auth" onclick="fillLogin(&quot;admin' OR '1'='1&quot;, 'anything')">
              🔓 Fill SQLi Auth Bypass: admin' OR '1'='1
            </button>
            <button type="button" class="btn btn-danger-soft btn-sm" id="btn-preset-sqli-comment" onclick="fillLogin(&quot;admin' -- &quot;, 'ignored')">
              🔓 Fill SQLi Comment Bypass: admin' --
            </button>
          </div>

          <form id="login-form" action="/login" method="POST">
            <div class="form-group">
              <label for="login-username">Username</label>
              <input class="form-control" type="text" id="login-username" name="username" value="demo_user" oninput="updateSqlPreview()" required />
            </div>
            <div class="form-group">
              <label for="login-password">Password</label>
              <input class="form-control" type="text" id="login-password" name="password" value="CloudArmor2026!" oninput="updateSqlPreview()" required />
            </div>

            <div class="form-group">
              <label>Backend SQL Query Constructed Live:</label>
              <div class="code-box" id="sql-live-preview"></div>
            </div>

            <div style="display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:16px;">
              <button type="submit" class="btn btn-primary" id="btn-login-submit">
                Sign In &amp; Enter Next Page (/portal/dashboard) &rarr;
              </button>
              <button type="button" class="btn btn-outline" id="btn-login-ajax" onclick="testLoginInline()">
                Test Inline (Stay on Page &amp; Inspect HTTP Status)
              </button>
            </div>
          </form>

          <div id="login-inline-result" style="margin-top:16px; display:none;"></div>
        </div>

        <div class="card">
          <h3>How to Compare Pre-Armor vs. Post-Armor in Your Browser</h3>
          <div class="alert-box alert-warn">
            <strong>Why do you see <code>403 Forbidden</code> right now when clicking the SQLi preset?</strong><br/>
            Because Cloud Armor policy <code>cloud-armor-study-policy-01</code> is currently <strong>attached &amp; enforced</strong> on <code>gcp2-xlb</code>! When you submit <code>admin' OR '1'='1</code>, Google Cloud Armor intercepts the request at the load balancer edge and blocks it before it ever reaches Cloud Run.
          </div>

          <p style="font-size:0.88rem; margin-bottom:8px;"><strong>Step 1 — See the Vulnerability Succeed (Pre-Armor):</strong></p>
          <p class="subtext" style="margin-bottom:8px;">
            Detach the policy in <strong>Google Cloud Console &rarr; Cloud Armor &rarr; Policies &rarr; <code>cloud-armor-study-policy-01</code> &rarr; Targets &rarr; Remove</strong> (or run <code>./scripts/toggle_armor.sh detach</code>), wait ~60s, then click <strong>Fill SQLi Auth Bypass</strong> and <strong>Sign In</strong>. You will bypass authentication and enter the <strong>Executive Vault Next Page</strong> as <code>admin</code>!
          </p>

          <p style="font-size:0.88rem; margin-bottom:8px;"><strong>Step 2 — See Cloud Armor Block the Attack (Post-Armor):</strong></p>
          <p class="subtext" style="margin-bottom:12px;">
            Re-attach <code>cloud-armor-study-policy-01</code> to <code>cloud-armor-demo-backend-svc</code> (or run <code>./scripts/toggle_armor.sh attach</code>). Now:
          </p>
          <ul style="font-size:0.86rem; color:var(--text-muted); padding-left:18px; margin-top:0;">
            <li><strong>Valid Login (<code>demo_user</code> / <code>CloudArmor2026!</code>):</strong> Allowed by Cloud Armor (<code>HTTP 200</code>) and enters the Next Page!</li>
            <li><strong>SQLi Bypass (<code>admin' OR '1'='1</code>):</strong> Blocked at the edge by <strong>Priority 2000 (<code>sqli-v33-stable</code>)</strong> with <code>HTTP 403 Forbidden</code>!</li>
          </ul>

          <h3 style="margin-top:18px;">Seeded Study Accounts in SQLite</h3>
          <table class="data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Password</th>
                <th>Clearance</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code>admin</code></td>
                <td><em>(Secret — target for SQLi bypass)</em></td>
                <td><code>LEVEL_5_EXECUTIVE_VAULT</code></td>
              </tr>
              <tr>
                <td><code>demo_user</code></td>
                <td><code>CloudArmor2026!</code></td>
                <td><code>LEVEL_1_STANDARD</code></td>
              </tr>
              <tr>
                <td><code>indrapn</code></td>
                <td><code>ArgolisStudy!2026</code></td>
                <td><code>LEVEL_4_ARCHITECT</code></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- TAB 2: SEARCH & XSS FILTER -->
    <section class="tab-panel" id="panel-xss" role="tabpanel">
      <div class="grid-2">
        <div class="card">
          <h2>Search &amp; Feedback Wall (OWASP XSS WAF Rule Study)</h2>
          <p class="subtext">
            Tests how reflected HTML/JavaScript vectors in query parameters are handled before and after attaching <strong>Cloud Armor Priority 2000 (<code>xss-v33-stable</code>)</strong>.
          </p>
          <div class="preset-bar">
            <button type="button" class="btn btn-success-soft btn-sm" onclick="fillSearch('Cloud Armor WAF architecture')">
              ✅ Fill Normal Search Query
            </button>
            <button type="button" class="btn btn-danger-soft btn-sm" onclick="fillSearch('&lt;script&gt;alert(&quot;XSS-Study-Test&quot;)&lt;/script&gt;')">
              🔓 Fill Reflected Script Vector (&lt;script&gt;...)
            </button>
            <button type="button" class="btn btn-danger-soft btn-sm" onclick="fillSearch('&lt;img src=x onerror=alert(1)&gt;')">
              🔓 Fill Event Handler Vector (onerror=...)
            </button>
          </div>
          <form action="/search" method="GET" id="search-form">
            <div class="form-group">
              <label for="search-input">Search Term (<code>GET /search?q=...</code>)</label>
              <input class="form-control" type="text" id="search-input" name="q" value="Cloud Armor WAF architecture" required />
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
              <button type="submit" class="btn btn-primary" id="btn-search-submit">
                Submit Search &amp; Open Results Page (/search) &rarr;
              </button>
              <button type="button" class="btn btn-outline" onclick="testEndpointInline('/search?q=' + encodeURIComponent(document.getElementById('search-input').value), {}, 'xss-inline-result')">
                Test Inline
              </button>
            </div>
          </form>
          <div id="xss-inline-result" style="margin-top:16px; display:none;"></div>
        </div>

        <div class="card">
          <h3>Enforcing Rule: Priority 2000 (<code>xss-v33-stable</code>)</h3>
          <div class="code-box">evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1}) ||
evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})</div>
          <p class="subtext">
            When Cloud Armor is detached, submitting <code>&lt;script&gt;alert("XSS-Study-Test")&lt;/script&gt;</code> reaches the Cloud Run origin and opens the <code>/search</code> results page showing an unfiltered XSS detection banner. When Cloud Armor is attached, the GFE blocks the request at the edge with <code>HTTP 403 Forbidden</code>.
          </p>
        </div>
      </div>
    </section>

    <!-- TAB 3: LFI & RCE WAF RULES -->
    <section class="tab-panel" id="panel-lfirce" role="tabpanel">
      <div class="grid-2">
        <div class="card">
          <h2>Document Viewer &amp; Ping Utility (OWASP LFI &amp; RCE WAF Study)</h2>
          <p class="subtext">
            Safe, sandboxed simulation of file path lookup and diagnostic command parameters protected by <strong>Cloud Armor Priority 2100 (<code>lfi-v33-stable</code> &amp; <code>rce-v33-stable</code>)</strong>.
          </p>
          <div class="preset-bar">
            <button type="button" class="btn btn-success-soft btn-sm" onclick="fillViewer('architecture-overview.txt', '8.8.8.8')">
              ✅ Fill Safe Document &amp; Host
            </button>
            <button type="button" class="btn btn-danger-soft btn-sm" onclick="fillViewer('../../../../etc/passwd', '8.8.8.8')">
              🔓 Fill LFI Path Traversal (../../../../etc/passwd)
            </button>
            <button type="button" class="btn btn-danger-soft btn-sm" onclick="fillViewer('architecture-overview.txt', '8.8.8.8; cat /etc/passwd')">
              🔓 Fill RCE Command Chaining (8.8.8.8; cat /etc/passwd)
            </button>
          </div>
          <form action="/viewer" method="GET">
            <div class="form-group">
              <label for="viewer-doc">Document Name (<code>doc</code> parameter)</label>
              <input class="form-control" type="text" id="viewer-doc" name="doc" value="architecture-overview.txt" />
            </div>
            <div class="form-group">
              <label for="viewer-target">Diagnostic Ping Target (<code>target</code> parameter)</label>
              <input class="form-control" type="text" id="viewer-target" name="target" value="8.8.8.8" />
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
              <button type="submit" class="btn btn-primary" id="btn-viewer-submit">
                Open Viewer Page (/viewer) &rarr;
              </button>
              <button type="button" class="btn btn-outline" onclick="testEndpointInline('/viewer?doc=' + encodeURIComponent(document.getElementById('viewer-doc').value) + '&target=' + encodeURIComponent(document.getElementById('viewer-target').value), {}, 'lfirce-inline-result')">
                Test Inline
              </button>
            </div>
          </form>
          <div id="lfirce-inline-result" style="margin-top:16px; display:none;"></div>
        </div>

        <div class="card">
          <h3>Enforcing Rule: Priority 2100 (<code>lfi-v33-stable</code> &amp; <code>rce-v33-stable</code>)</h3>
          <div class="code-box">evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1}) ||
evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 1}) ||
evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': 1})</div>
          <p class="subtext">
             Note: This Cloud Run container never touches the OS filesystem or shell—it matches against an in-memory dictionary so you can safely observe LFI/RCE pattern detection before and after Cloud Armor enforcement.
          </p>
        </div>
      </div>
    </section>

    <!-- TAB 4: ADMIN DIAGNOSTICS & CUSTOM CEL RULES -->
    <section class="tab-panel" id="panel-cel" role="tabpanel">
      <div class="grid-2">
        <div class="card">
          <h2>Custom CEL Policy Verification (Priority 1000 &amp; 1100)</h2>
          <p class="subtext">
            Test Cloud Armor Custom Common Expression Language (CEL) rules directly from your browser using <code>fetch()</code> with custom HTTP headers and query strings.
          </p>

          <div style="display:flex; flex-direction:column; gap:10px;">
            <button type="button" class="btn btn-danger-soft" onclick="testEndpointInline('/admin/diagnostics', {}, 'cel-inline-result')">
              1. Request /admin/diagnostics WITHOUT X-Admin-Token (Pre-Armor: 200 Exposed | Post-Armor: 403 Blocked by P1000)
            </button>
            <button type="button" class="btn btn-success-soft" onclick="testEndpointInline('/admin/diagnostics', {'X-Admin-Token': 'study-secret-2026'}, 'cel-inline-result')">
              2. Request /admin/diagnostics WITH Valid X-Admin-Token: study-secret-2026 (Allowed HTTP 200)
            </button>
            <button type="button" class="btn btn-danger-soft" onclick="testEndpointInline('/api/inspect', {'X-Policy-Test': 'block-me'}, 'cel-inline-result')">
              3. Request /api/inspect WITH Header X-Policy-Test: block-me (Post-Armor: 403 Blocked by P1100)
            </button>
            <button type="button" class="btn btn-danger-soft" onclick="testEndpointInline('/api/inspect?policy_test=block', {}, 'cel-inline-result')">
              4. Request /api/inspect?policy_test=block (Post-Armor: 403 Blocked by P1100)
            </button>
          </div>

          <div id="cel-inline-result" style="margin-top:16px; display:none;"></div>
        </div>

        <div class="card">
          <h3>Custom CEL Expressions Configured on <code>gcp2-xlb</code></h3>
          <p style="font-size:0.86rem; font-weight:600; margin-bottom:4px;">Priority 1000 — Protect <code>/admin/*</code>:</p>
          <div class="code-box">request.path.startsWith('/admin') &amp;&amp;
(!has(request.headers['x-admin-token']) ||
 request.headers['x-admin-token'] != 'study-secret-2026')</div>
          <p style="font-size:0.86rem; font-weight:600; margin-bottom:4px;">Priority 1100 — Block Test Marker Header or Query:</p>
          <div class="code-box">(has(request.headers['x-policy-test']) &amp;&amp;
 request.headers['x-policy-test'] == 'block-me') ||
request.query.contains('policy_test=block')</div>
        </div>
      </div>
    </section>

    <!-- TAB 5: RATE LIMITING BURST TESTER -->
    <section class="tab-panel" id="panel-rate" role="tabpanel">
      <div class="card">
        <h2>Interactive Rate-Limiting Burst Simulator (Priority 3000 — <code>/api/ping</code>)</h2>
        <p class="subtext">
          Fires <strong>18 rapid requests</strong> from your browser to <code>GET /api/ping</code>.
          <strong>Pre-Armor:</strong> All 18 requests return <code>HTTP 200 OK</code>.
          <strong>Post-Armor:</strong> Cloud Armor Priority 3000 (<code>throttle</code> at <code>10</code> requests per <code>60s</code> per client IP) allows the first 10 requests and throttles excess requests at the edge with <strong><code>HTTP 429 Too Many Requests</code></strong>.
        </p>
        <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
          <button type="button" class="btn btn-primary" id="btn-run-burst" onclick="runBurstTest()">
            ⚡ Fire 18 Rapid Requests to /api/ping
          </button>
          <span id="burst-summary-badge" class="badge badge-blue">Ready to run burst test</span>
        </div>
        <div class="burst-grid" id="burst-grid"></div>
      </div>
    </section>
  </main>

  <script>
    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
      document.getElementById('tab-btn-' + tabId).classList.add('active');
      document.getElementById('panel-' + tabId).classList.add('active');
    }

    function updateSqlPreview() {
      const u = document.getElementById('login-username').value;
      const p = document.getElementById('login-password').value;
      const sql = "SELECT id, username, role, clearance, vault_note\\nFROM study_users\\nWHERE username = '" + u + "' AND password = '" + p + "';";
      document.getElementById('sql-live-preview').textContent = sql;
    }

    function fillLogin(username, password) {
      document.getElementById('login-username').value = username;
      document.getElementById('login-password').value = password;
      updateSqlPreview();
    }

    function fillSearch(q) {
      document.getElementById('search-input').value = q;
    }

    function fillViewer(doc, target) {
      document.getElementById('viewer-doc').value = doc;
      document.getElementById('viewer-target').value = target;
    }

    async function testLoginInline() {
      const u = document.getElementById('login-username').value;
      const p = document.getElementById('login-password').value;
      const box = document.getElementById('login-inline-result');
      box.style.display = 'block';
      box.innerHTML = '<div class="alert-box alert-warn">Sending POST /login request through gcp2-xlb...</div>';
      const body = new URLSearchParams({username: u, password: p});
      try {
        const resp = await fetch('/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Inline-Check': 'true'},
          body: body.toString()
        });
        const text = await resp.text();
        if (resp.status === 403) {
          box.innerHTML = '<div class="alert-box alert-danger"><strong>🛡️ BLOCKED AT EDGE BY GOOGLE CLOUD ARMOR (HTTP 403 Forbidden)</strong><br/>' +
            'Cloud Armor Priority 2000 (<code>sqli-v33-stable</code>) intercepted the SQL Injection payload at <code>gcp2-xlb</code> before it reached Cloud Run!<br/>' +
            '<div class="code-box">' + escapeHtml(text.slice(0, 400)) + '</div></div>';
        } else if (resp.status === 200) {
          box.innerHTML = '<div class="alert-box alert-success"><strong>✅ HTTP 200 OK — Request Reached Cloud Run &amp; Authenticated!</strong><br/>' +
            'Click <strong>"Sign In &amp; Enter Next Page"</strong> to view the full authenticated dashboard page.</div>';
        } else {
          box.innerHTML = '<div class="alert-box alert-warn"><strong>HTTP ' + resp.status + '</strong><div class="code-box">' + escapeHtml(text.slice(0, 400)) + '</div></div>';
        }
      } catch (err) {
        box.innerHTML = '<div class="alert-box alert-danger">Request error: ' + escapeHtml(String(err)) + '</div>';
      }
    }

    async function testEndpointInline(url, headers, targetDivId) {
      const box = document.getElementById(targetDivId);
      box.style.display = 'block';
      box.innerHTML = '<div class="alert-box alert-warn">Requesting <code>' + escapeHtml(url) + '</code>...</div>';
      try {
        const resp = await fetch(url, {headers: headers || {}});
        const text = await resp.text();
        const isBlocked = resp.status === 403 || resp.status === 429;
        const alertClass = isBlocked ? 'alert-danger' : 'alert-success';
        const title = isBlocked
          ? '🛡️ BLOCKED AT EDGE BY CLOUD ARMOR (HTTP ' + resp.status + ')'
          : '✅ ALLOWED THROUGH EDGE TO CLOUD RUN (HTTP ' + resp.status + ')';
        box.innerHTML = '<div class="alert-box ' + alertClass + '"><strong>' + title + '</strong>' +
          '<div class="code-box">' + escapeHtml(text.slice(0, 700)) + '</div></div>';
      } catch (err) {
        box.innerHTML = '<div class="alert-box alert-danger">Error: ' + escapeHtml(String(err)) + '</div>';
      }
    }

    async function runBurstTest() {
      const grid = document.getElementById('burst-grid');
      const badge = document.getElementById('burst-summary-badge');
      grid.innerHTML = '';
      badge.className = 'badge badge-amber';
      badge.textContent = 'Firing 18 rapid requests...';
      let okCount = 0;
      let throttledCount = 0;

      for (let i = 1; i <= 18; i++) {
        const tile = document.createElement('div');
        tile.className = 'burst-tile';
        tile.id = 'burst-tile-' + i;
        tile.innerHTML = '<strong>#' + i + '</strong><br/>Sending...';
        grid.appendChild(tile);
      }

      for (let i = 1; i <= 18; i++) {
        const tile = document.getElementById('burst-tile-' + i);
        try {
          const resp = await fetch('/api/ping?seq=' + i + '&t=' + Date.now(), {cache: 'no-store'});
          if (resp.status === 200) {
            okCount++;
            tile.className = 'burst-tile ok';
            tile.innerHTML = '<strong>#' + i + '</strong><br/>HTTP 200 OK';
          } else {
            throttledCount++;
            tile.className = 'burst-tile throttled';
            tile.innerHTML = '<strong>#' + i + '</strong><br/>HTTP ' + resp.status;
          }
        } catch (e) {
          tile.className = 'burst-tile throttled';
          tile.innerHTML = '<strong>#' + i + '</strong><br/>Error';
        }
      }

      badge.className = throttledCount > 0 ? 'badge badge-red' : 'badge badge-green';
      badge.textContent = 'Completed: HTTP 200 = ' + okCount + '/18 | Throttled (HTTP 429) = ' + throttledCount + '/18';
    }

    function escapeHtml(str) {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    updateSqlPreview();
  </script>
</body>
</html>"""
    return (
        template.replace("__SHARED_CSS__", SHARED_CSS)
        .replace("__SERVICE_NAME__", html.escape(SERVICE_NAME))
        .replace("__GCP_REGION__", html.escape(GCP_REGION))
        .replace("__CLIENT_IP__", client_ip)
        .replace("__HOST__", host)
        .replace("__VIA_XLB__", via_xlb)
    )


def _render_dashboard_page_html(
    username_input: str,
    password_input: str,
    raw_sql: str,
    matched_rows: List[Dict[str, Any]],
    sql_error: Optional[str],
    request: Request,
) -> Tuple[int, str]:
    """Renders the 'Next Page' (/portal/dashboard) after the user submits the Login form."""
    ctx = _extract_request_context(request)
    is_sqli_pattern = (
        "'" in username_input
        or "'" in password_input
        or "--" in username_input
        or "--" in password_input
        or " or " in username_input.lower()
        or " or " in password_input.lower()
        or "union" in username_input.lower()
        or "union" in password_input.lower()
    )

    if not matched_rows:
        status_code = 401
        banner_html = f"""
        <div class="alert-box alert-danger">
          <strong>❌ Authentication Failed (0 rows returned)</strong><br/>
          Neither valid credentials nor an SQL tautology matched any rows in <code>study_users</code>.
          {f'<br/><strong>SQLite Error:</strong> <code>{html.escape(sql_error)}</code>' if sql_error else ''}
        </div>
        """
        body_section = """
        <p>Return to the Login tab and click either <strong>Fill Valid User</strong> or (when Cloud Armor is detached) <strong>Fill SQLi Auth Bypass</strong>.</p>
        """
    else:
        status_code = 200
        primary_user = matched_rows[0]
        if is_sqli_pattern:
            banner_html = """
            <div class="alert-box alert-danger">
              <strong>🔓 VULNERABILITY CONFIRMED (PRE-ARMOR STATE): SQL Injection Authentication Bypass Succeeded!</strong><br/>
              Because Google Cloud Armor is currently detached (or in preview mode), your SQL injection payload reached the Cloud Run backend and bypassed password verification, logging you directly into the <strong>Executive Vault Next Page</strong>!
            </div>
            """
        else:
            banner_html = """
            <div class="alert-box alert-success">
              <strong>✅ LEGITIMATE SIGN-IN SUCCEEDED: Clean Request Allowed by Google Cloud Armor!</strong><br/>
              Your clean credentials passed through <code>gcp2-xlb</code> and Google Cloud Armor without triggering any OWASP WAF rules, and authenticated normally into the Next Page.
            </div>
            """

        rows_html = "".join(
            f"""
            <tr>
              <td><code>{html.escape(str(r['id']))}</code></td>
              <td><strong>{html.escape(str(r['username']))}</strong></td>
              <td>{html.escape(str(r['role']))}</td>
              <td><span class="badge badge-blue">{html.escape(str(r['clearance']))}</span></td>
              <td><code>{html.escape(str(r['vault_note']))}</code></td>
            </tr>
            """
            for r in matched_rows
        )

        body_section = f"""
        <div class="grid-2">
          <div class="card">
            <h2>Unlocked Next Page: Executive Vault Session</h2>
            <p class="subtext">You are now inside the post-login portal page (<code>/portal/dashboard</code>).</p>
            <table class="data-table">
              <tbody>
                <tr><th>Active Session Account</th><td><strong>{html.escape(str(primary_user['username']))}</strong></td></tr>
                <tr><th>Assigned Role</th><td>{html.escape(str(primary_user['role']))}</td></tr>
                <tr><th>Security Clearance</th><td><span class="badge badge-green">{html.escape(str(primary_user['clearance']))}</span></td></tr>
                <tr><th>Authentication Mode</th><td>{"⚠️ SQL Injection Tautology Bypass (Unprotected Origin)" if is_sqli_pattern else "✅ Standard Credential Match"}</td></tr>
                <tr><th>Vault Secret / Note</th><td><code>{html.escape(str(primary_user['vault_note']))}</code></td></tr>
              </tbody>
            </table>
          </div>

          <div class="card">
            <h3>Executed Backend SQL Statement</h3>
            <div class="code-box">{html.escape(raw_sql)}</div>
            <p class="subtext">
              <strong>Why did this happen?</strong> The login handler concatenated your input directly into the SQL string.
              When <code>cloud-armor-study-policy-01</code> is attached on <code>gcp2-xlb</code>, <strong>Rule Priority 2000 (<code>sqli-v33-stable</code>)</strong> detects the SQL injection tokens at Google's edge and blocks the request with <code>HTTP 403 Forbidden</code> before it ever reaches this page.
            </p>
          </div>
        </div>

        <div class="card" style="margin-top:20px;">
          <h3>Database Records Returned by Query ({len(matched_rows)} row(s) unlocked)</h3>
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>Clearance</th>
                <th>Internal Vault Record</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>
        """

    page_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Executive Vault Portal — Cloud Armor Study Next Page</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>{SHARED_CSS}</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand-title">
        <span class="badge badge-blue">🛡️ Cloud Armor Study Lab</span>
        <h1>Executive Vault Portal (Post-Login Next Page)</h1>
      </div>
      <div>
        <a href="/" class="btn btn-outline btn-sm" id="btn-back-home">&larr; Back to Login &amp; Study Lab</a>
      </div>
    </div>
  </header>
  <main class="container">
    {banner_html}
    {body_section}
    <div style="margin-top:20px;">
      <a href="/" class="btn btn-primary">&larr; Return to Cloud Armor Study Portal</a>
    </div>
  </main>
</body>
</html>"""
    return status_code, page_html


@app.get("/")
async def root_portal(request: Request):
    """
    Serves the interactive Web Browser Study Portal HTML page by default.
    If the caller explicitly requests `Accept: application/json`, returns the JSON status.
    """
    accept = request.headers.get("accept", "").lower()
    if "application/json" in accept and "text/html" not in accept:
        return await api_status(request)
    return HTMLResponse(
        content=_render_study_portal_html(request), status_code=200
    )


@app.get("/api/status")
async def api_status(request: Request) -> JSONResponse:
    """Public JSON baseline endpoint returning service metadata and study routes."""
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
                "/": "Interactive Web Browser Study Lab (HTML UI)",
                "/login": "Interactive SQLi Login form handler -> enters /portal/dashboard",
                "/portal/dashboard": "Authenticated Executive Vault Next Page",
                "/search": "Interactive XSS Search study page",
                "/viewer": "Interactive LFI/RCE WAF rule study page",
                "/healthz": "Health check endpoint",
                "/admin/diagnostics": (
                    "Mock admin diagnostics route (Protected by Priority 1000 Custom CEL rule)."
                ),
                "/api/inspect": (
                    "Header & query inspection echo endpoint (Protected by Priority 1100 Custom CEL rule)."
                ),
                "/api/ping": (
                    "Rate-limit test endpoint (Protected by Priority 3000 Throttle rule: 10 req/60s)."
                ),
            },
        },
    )


@app.api_route("/login", methods=["GET", "POST"])
async def login_handler(request: Request) -> HTMLResponse:
    """
    Handles the browser Login form submission (both POST form-urlencoded and GET query params)
    and renders the Next Page (/portal/dashboard) when authentication or SQLi bypass succeeds.
    """
    username = ""
    password = ""

    if request.method == "POST":
        raw_body = (await request.body()).decode("utf-8", errors="replace")
        content_type = request.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            try:
                data = json.loads(raw_body)
                username = str(data.get("username", ""))
                password = str(data.get("password", ""))
            except Exception:
                pass
        else:
            parsed = parse_qs(raw_body, keep_blank_values=True)
            username = parsed.get("username", [""])[0]
            password = parsed.get("password", [""])[0]

    if not username and "username" in request.query_params:
        username = request.query_params.get("username", "")
        password = request.query_params.get("password", "")

    raw_sql, matched_rows, sql_error = _evaluate_study_login_query(
        username, password
    )
    status_code, page_html = _render_dashboard_page_html(
        username, password, raw_sql, matched_rows, sql_error, request
    )
    return HTMLResponse(content=page_html, status_code=status_code)


@app.get("/portal/dashboard")
async def portal_dashboard(request: Request) -> HTMLResponse:
    """Direct view of the Next Page (/portal/dashboard) for session inspection."""
    user = request.query_params.get("user", "demo_user")
    raw_sql, matched_rows, sql_error = _evaluate_study_login_query(
        user, "CloudArmor2026!" if user == "demo_user" else ""
    )
    if not matched_rows:
        # Show demo_user by default if navigated directly
        raw_sql, matched_rows, sql_error = _evaluate_study_login_query(
            "demo_user", "CloudArmor2026!"
        )
    status_code, page_html = _render_dashboard_page_html(
        user, "***", raw_sql, matched_rows, sql_error, request
    )
    return HTMLResponse(content=page_html, status_code=status_code)


@app.get("/search")
async def search_page(request: Request) -> HTMLResponse:
    """
    Interactive Search results page demonstrating reflected input detection (Pre-Armor)
    vs. OWASP XSS WAF blocking (`xss-v33-stable` Priority 2000 Post-Armor).
    Note: Output is HTML-escaped in the browser DOM for safety while clearly displaying
    whether an unescaped script vector reached the Cloud Run origin.
    """
    q = request.query_params.get("q", "")
    lower_q = q.lower()
    has_xss_pattern = (
        "<script" in lower_q
        or "onerror=" in lower_q
        or "onload=" in lower_q
        or "javascript:" in lower_q
        or "<img" in lower_q
        or "<svg" in lower_q
    )

    if has_xss_pattern:
        banner = """
        <div class="alert-box alert-danger">
          <strong>⚠️ UNFILTERED XSS VECTOR REACHED ORIGIN (PRE-ARMOR STATE)!</strong><br/>
          Your input contained an HTML/JavaScript injection signature that reached the Cloud Run backend because Cloud Armor is detached.
          When <code>cloud-armor-study-policy-01</code> is attached, <strong>Priority 2000 (<code>xss-v33-stable</code>)</strong> blocks this request at the load balancer edge with <code>HTTP 403 Forbidden</code>.
        </div>
        """
    else:
        banner = """
        <div class="alert-box alert-success">
          <strong>✅ Clean Search Query Processed</strong><br/>
          No XSS signature detected. Allowed through <code>gcp2-xlb</code> and Cloud Armor.
        </div>
        """

    page_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Search Results — Cloud Armor XSS Study</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>{SHARED_CSS}</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand-title">
        <span class="badge badge-blue">🛡️ Cloud Armor Study Lab</span>
        <h1>Search Results Page (XSS WAF Verification)</h1>
      </div>
      <div>
        <a href="/" class="btn btn-outline btn-sm">&larr; Back to Study Lab</a>
      </div>
    </div>
  </header>
  <main class="container">
    {banner}
    <div class="card">
      <h2>Search Query Received by Cloud Run Origin</h2>
      <div class="code-box">{html.escape(q)}</div>
      <p class="subtext">
        <em>(Safe Study Rendering: The string above is displayed in a literal code block so you can safely verify in your browser whether the request reached the origin container without executing arbitrary scripts in your browser session.)</em>
      </p>
      <a href="/" class="btn btn-primary">&larr; Back to Study Lab</a>
    </div>
  </main>
</body>
</html>"""
    return HTMLResponse(content=page_html, status_code=200)


@app.get("/viewer")
async def viewer_page(request: Request) -> HTMLResponse:
    """
    Safe, sandboxed Document Viewer & Ping page illustrating LFI (`lfi-v33-stable`)
    and RCE (`rce-v33-stable`) WAF rule inspection at Priority 2100.
    """
    doc = request.query_params.get("doc", "architecture-overview.txt")
    target = request.query_params.get("target", "8.8.8.8")

    is_lfi = ".." in doc or "/etc/" in doc or "\\windows\\" in doc.lower()
    is_rce = any(sep in target for sep in [";", "|", "&&", "`", "$("])

    if is_lfi or is_rce:
        banner = f"""
        <div class="alert-box alert-danger">
          <strong>⚠️ UNFILTERED {"LFI PATH TRAVERSAL" if is_lfi else "RCE COMMAND CHAINING"} REACHED ORIGIN (PRE-ARMOR STATE)!</strong><br/>
          This request reached the Cloud Run backend because Cloud Armor is detached.
          When <code>cloud-armor-study-policy-01</code> is attached on <code>gcp2-xlb</code>, <strong>Priority 2100 (<code>lfi-v33-stable</code> / <code>rce-v33-stable</code>)</strong> blocks this request at the edge with <code>HTTP 403 Forbidden</code>.
        </div>
        """
        doc_output = (
            "[SIMULATED SENSITIVE FILE EXPOSURE IN PRE-ARMOR MODE]\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "cloudrun-study:x:1000:1000:Study Service:/app:/bin/false"
        )
    else:
        banner = """
        <div class="alert-box alert-success">
          <strong>✅ Safe Document &amp; Diagnostic Target Allowed</strong><br/>
          Clean parameters passed through Cloud Armor Priority 2100 without triggering LFI or RCE rules.
        </div>
        """
        doc_output = MOCK_DOCUMENTS.get(
            doc, f"Document '{doc}' not found in study catalog."
        )

    page_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Document &amp; Ping Viewer — Cloud Armor LFI/RCE Study</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>{SHARED_CSS}</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand-title">
        <span class="badge badge-blue">🛡️ Cloud Armor Study Lab</span>
        <h1>Document &amp; Ping Viewer (LFI / RCE WAF Verification)</h1>
      </div>
      <div>
        <a href="/" class="btn btn-outline btn-sm">&larr; Back to Study Lab</a>
      </div>
    </div>
  </header>
  <main class="container">
    {banner}
    <div class="card">
      <h2>Inspected Parameters at Cloud Run Origin</h2>
      <p><strong>Requested Document (<code>doc</code>):</strong> <code>{html.escape(doc)}</code></p>
      <p><strong>Requested Ping Target (<code>target</code>):</strong> <code>{html.escape(target)}</code></p>
      <h3>Output Preview</h3>
      <div class="code-box">{html.escape(doc_output)}</div>
      <a href="/" class="btn btn-primary">&larr; Back to Study Lab</a>
    </div>
  </main>
</body>
</html>"""
    return HTMLResponse(content=page_html, status_code=200)


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
