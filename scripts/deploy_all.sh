#!/usr/bin/env bash
# End-to-end provisioning script for cloud-armor-study-01.
# Executes the exact verified CLI commands from study-notes.md (Sections 3.1, 3.2, and 5.4):
#   1. Deploys the Cloud Run service (with --ingress=internal-and-cloud-load-balancing)
#   2. Creates the regional Serverless NEG in asia-southeast2
#   3. Creates the global Backend Service and attaches the Serverless NEG
#   4. Adds the Host & Path Matcher for gcp2demo01.iphamsterviel.org to gcp2-xlb
#   5. Creates & configures the Cloud Armor security policy (cloud-armor-study-policy-01)
#   6. Attaches the Cloud Armor policy to the backend service
#
# Usage (from repository root):
#   ./scripts/deploy_all.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/env.sh"

cd "${REPO_ROOT}"

echo "[1] Deploying Cloud Run service '${SERVICE_NAME}' in '${REGION}' (ingress=internal-and-cloud-load-balancing)..."
gcloud run deploy "${SERVICE_NAME}" \
  --source=./app \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --allow-unauthenticated \
  --ingress=internal-and-cloud-load-balancing \
  --min-instances=1 \
  --max-instances=5 \
  --quiet

echo "[2] Creating Serverless NEG '${NEG_NAME}' in '${REGION}' (if not already present)..."
if ! gcloud compute network-endpoint-groups describe "${NEG_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute network-endpoint-groups create "${NEG_NAME}" \
    --region="${REGION}" \
    --network-endpoint-type=serverless \
    --cloud-run-service="${SERVICE_NAME}" \
    --project="${PROJECT_ID}"
else
  echo "    Serverless NEG '${NEG_NAME}' already exists."
fi

echo "[3] Creating global Backend Service '${BACKEND_SERVICE_NAME}' & attaching NEG (if not already present)..."
if ! gcloud compute backend-services describe "${BACKEND_SERVICE_NAME}" --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute backend-services create "${BACKEND_SERVICE_NAME}" \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --enable-logging \
    --logging-sample-rate=1.0 \
    --logging-optional=INCLUDE_ALL_OPTIONAL \
    --global \
    --project="${PROJECT_ID}"

  gcloud compute backend-services add-backend "${BACKEND_SERVICE_NAME}" \
    --global \
    --network-endpoint-group="${NEG_NAME}" \
    --network-endpoint-group-region="${REGION}" \
    --project="${PROJECT_ID}"
else
  echo "    Backend service '${BACKEND_SERVICE_NAME}' already exists."
fi

echo "[4] Ensuring host rule '${DEMO_DOMAIN}' -> '${BACKEND_SERVICE_NAME}' exists on '${XLB_URL_MAP}'..."
EXISTING_HOST="$(gcloud compute url-maps describe "${XLB_URL_MAP}" --global --project="${PROJECT_ID}" --format="json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for hr in data.get('hostRules', []):
    if '${DEMO_DOMAIN}' in hr.get('hosts', []):
        print(hr.get('pathMatcher', ''))
")"
if [[ -z "${EXISTING_HOST}" ]]; then
  gcloud compute url-maps add-path-matcher "${XLB_URL_MAP}" \
    --path-matcher-name="${PATH_MATCHER_NAME}" \
    --default-service="${BACKEND_SERVICE_NAME}" \
    --new-hosts="${DEMO_DOMAIN}" \
    --global \
    --project="${PROJECT_ID}"
else
  echo "    Host '${DEMO_DOMAIN}' is already routed via path matcher '${EXISTING_HOST}'."
fi

echo "[5] Creating & configuring Cloud Armor security policy '${SECURITY_POLICY_NAME}'..."
if ! gcloud compute security-policies describe "${SECURITY_POLICY_NAME}" --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute security-policies create "${SECURITY_POLICY_NAME}" \
    --type=CLOUD_ARMOR \
    --global \
    --description="Google Cloud Armor Defensive Study Policy (OWASP CRS v3.3 WAF, Custom CEL access/marker rules, and Rate Limiting)" \
    --project="${PROJECT_ID}"

  gcloud compute security-policies update "${SECURITY_POLICY_NAME}" \
    --global \
    --json-parsing=STANDARD \
    --log-level=VERBOSE \
    --project="${PROJECT_ID}"

  gcloud compute security-policies rules create 1000 \
    --security-policy="${SECURITY_POLICY_NAME}" \
    --action=deny-403 \
    --expression='request.path.startsWith("/admin") && (!has(request.headers["x-admin-token"]) || request.headers["x-admin-token"] != "study-secret-2026")' \
    --description="Block unauthorized access to /admin endpoints unless valid X-Admin-Token header is provided" \
    --project="${PROJECT_ID}"

  gcloud compute security-policies rules create 1100 \
    --security-policy="${SECURITY_POLICY_NAME}" \
    --action=deny-403 \
    --expression="(has(request.headers['x-policy-test']) && request.headers['x-policy-test'] == 'block-me') || request.query.contains('policy_test=block')" \
    --description="Block requests carrying benign policy verification marker in X-Policy-Test header or query parameter" \
    --project="${PROJECT_ID}"

  gcloud compute security-policies rules create 2000 \
    --security-policy="${SECURITY_POLICY_NAME}" \
    --action=deny-403 \
    --expression="evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 3}) || evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 2})" \
    --description="Block SQLi (Sensitivity 3) and XSS (Sensitivity 2) using OWASP CRS v3.3 preconfigured WAF rules" \
    --project="${PROJECT_ID}"

  gcloud compute security-policies rules create 2100 \
    --security-policy="${SECURITY_POLICY_NAME}" \
    --action=deny-403 \
    --expression="evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 2}) || evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 2}) || evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': 2})" \
    --description="Block LFI, RCE, and Scanner probes using OWASP CRS v3.3 preconfigured WAF rules (Sensitivity 2)" \
    --project="${PROJECT_ID}"

  gcloud compute security-policies rules create 3000 \
    --security-policy="${SECURITY_POLICY_NAME}" \
    --action=throttle \
    --expression="request.path.startsWith('/api/ping')" \
    --rate-limit-threshold-count=10 \
    --rate-limit-threshold-interval-sec=60 \
    --conform-action=allow \
    --exceed-action=deny-429 \
    --enforce-on-key=IP \
    --description="Rate limit /api/ping to 10 requests per 60 seconds per client IP (exceed returns HTTP 429)" \
    --project="${PROJECT_ID}"
else
  echo "    Security policy '${SECURITY_POLICY_NAME}' already exists."
fi

echo "[6] Attaching '${SECURITY_POLICY_NAME}' to '${BACKEND_SERVICE_NAME}'..."
gcloud compute backend-services update "${BACKEND_SERVICE_NAME}" \
  --global \
  --security-policy="${SECURITY_POLICY_NAME}" \
  --project="${PROJECT_ID}" \
  --quiet

echo "[+] Full deployment completed! Wait ~60s for edge propagation, then test https://${DEMO_DOMAIN}/"
