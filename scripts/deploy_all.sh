#!/usr/bin/env bash
# End-to-end provisioning script for cloud-armor-study-01.
# Deploys the Cloud Run service (with restricted ingress), Serverless NEG,
# global Backend Service, gcp2-xlb Host & Path Matcher for gcp2demo01.iphamsterviel.org
# (preserving all existing routes on gcp2-xlb), and the Cloud Armor security policy.
#
# Usage:
#   ./scripts/deploy_all.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/env.sh"

echo "[1] Deploying Cloud Run service '${SERVICE_NAME}' in '${REGION}' (ingress=internal-and-cloud-load-balancing)..."
gcloud run deploy "${SERVICE_NAME}" \
  --source="${REPO_ROOT}/app" \
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

echo "[3] Creating global Backend Service '${BACKEND_SERVICE_NAME}' (if not already present)..."
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
    --description="Google Cloud Armor Defensive Study Policy (OWASP CRS v3.3 WAF, Custom CEL access/marker rules, and Rate Limiting)" \
    --project="${PROJECT_ID}"
fi

gcloud compute security-policies import "${SECURITY_POLICY_NAME}" \
  --source="${REPO_ROOT}/cfg/cloud-armor-study-policy-01.yaml" \
  --project="${PROJECT_ID}" \
  --quiet

echo "[6] Attaching '${SECURITY_POLICY_NAME}' to '${BACKEND_SERVICE_NAME}'..."
gcloud compute backend-services update "${BACKEND_SERVICE_NAME}" \
  --global \
  --security-policy="${SECURITY_POLICY_NAME}" \
  --project="${PROJECT_ID}" \
  --quiet

echo "[+] Full deployment completed! Wait ~60s for edge propagation, then test https://${DEMO_DOMAIN}/"
