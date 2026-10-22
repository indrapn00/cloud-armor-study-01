#!/usr/bin/env bash
# Reverse-dependency cleanup script for cloud-armor-study-01.
# Strictly preserves all pre-existing routes, certificates, and backends on `gcp2-xlb`.
#
# Usage:
#   ./scripts/cleanup_resources.sh --policy-only   # Detach & delete only Cloud Armor policy
#   ./scripts/cleanup_resources.sh --all           # Delete policy, XLB route, backend service, NEG, and Cloud Run service

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

MODE="${1:---policy-only}"

echo "[1] Detaching Cloud Armor policy '${SECURITY_POLICY_NAME}' from '${BACKEND_SERVICE_NAME}'..."
gcloud compute backend-services update "${BACKEND_SERVICE_NAME}" \
  --global \
  --security-policy="" \
  --project="${PROJECT_ID}" \
  --quiet || true

echo "[2] Deleting Cloud Armor security policy '${SECURITY_POLICY_NAME}'..."
gcloud compute security-policies delete "${SECURITY_POLICY_NAME}" \
  --global \
  --project="${PROJECT_ID}" \
  --quiet || true

if [[ "${MODE}" == "--all" ]]; then
  echo "[3] Removing path matcher '${PATH_MATCHER_NAME}' (host '${DEMO_DOMAIN}') from '${XLB_URL_MAP}' (preserving existing routes)..."
  gcloud compute url-maps remove-path-matcher "${XLB_URL_MAP}" \
    --path-matcher-name="${PATH_MATCHER_NAME}" \
    --project="${PROJECT_ID}" \
    --quiet || true

  echo "[4] Deleting global backend service '${BACKEND_SERVICE_NAME}'..."
  gcloud compute backend-services delete "${BACKEND_SERVICE_NAME}" \
    --global \
    --project="${PROJECT_ID}" \
    --quiet || true

  echo "[5] Deleting Serverless NEG '${NEG_NAME}' in '${REGION}'..."
  gcloud compute network-endpoint-groups delete "${NEG_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet || true

  echo "[6] Deleting Cloud Run service '${SERVICE_NAME}' in '${REGION}'..."
  gcloud run services delete "${SERVICE_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet || true
fi

echo "[+] Cleanup (${MODE}) completed."
