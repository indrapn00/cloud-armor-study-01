#!/usr/bin/env bash
# Reverse-dependency cleanup script for cloud-armor-study-01.
# Strictly preserves all pre-existing routes, certificates, and backends on `gcp2-xlb`.
# Dynamically discovers the path matcher name on `gcp2-xlb` whether it was created via
# Google Cloud Console GUI (which auto-names it `path-matcher-1`, `matcher2`, etc.)
# or via `gcloud` CLI (`cloud-armor-demo-matcher`).
#
# Usage:
#   ./scripts/cleanup_resources.sh --policy-only   # Detach & delete only Cloud Armor policy
#   ./scripts/cleanup_resources.sh --all           # Delete policy, XLB route, backend service, NEG, and Cloud Run service

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

MODE="${1:---policy-only}"

echo "[1] Checking & detaching Cloud Armor policy from '${BACKEND_SERVICE_NAME}' (if backend service exists)..."
if gcloud compute backend-services describe "${BACKEND_SERVICE_NAME}" --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
  CURRENT_POLICY="$(gcloud compute backend-services describe "${BACKEND_SERVICE_NAME}" --global --project="${PROJECT_ID}" --format="value(securityPolicy)" || true)"
  if [[ -n "${CURRENT_POLICY}" ]]; then
    gcloud compute backend-services update "${BACKEND_SERVICE_NAME}" \
      --global \
      --security-policy="" \
      --project="${PROJECT_ID}" \
      --quiet
  else
    echo "    No security policy currently attached to '${BACKEND_SERVICE_NAME}'."
  fi
else
  echo "    Backend service '${BACKEND_SERVICE_NAME}' not found (already deleted)."
fi

echo "[2] Deleting Cloud Armor security policy '${SECURITY_POLICY_NAME}' (if present)..."
if gcloud compute security-policies describe "${SECURITY_POLICY_NAME}" --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud compute security-policies delete "${SECURITY_POLICY_NAME}" \
    --global \
    --project="${PROJECT_ID}" \
    --quiet
else
  echo "    Security policy '${SECURITY_POLICY_NAME}' not found (already deleted)."
fi

if [[ "${MODE}" == "--all" ]]; then
  echo "[3] Discovering & removing path matcher(s) for host '${DEMO_DOMAIN}' or backend '${BACKEND_SERVICE_NAME}' on '${XLB_URL_MAP}'..."
  URL_MAP_JSON="$(gcloud compute url-maps describe "${XLB_URL_MAP}" --global --project="${PROJECT_ID}" --format=json)"
  MATCHERS_TO_REMOVE="$(
    URL_MAP_JSON="${URL_MAP_JSON}" DEMO_DOMAIN="${DEMO_DOMAIN}" BACKEND_SERVICE_NAME="${BACKEND_SERVICE_NAME}" PATH_MATCHER_NAME="${PATH_MATCHER_NAME}" \
    python3 -c '
import json, os
data = json.loads(os.environ["URL_MAP_JSON"])
domain = os.environ["DEMO_DOMAIN"]
backend = os.environ["BACKEND_SERVICE_NAME"]
default_pm = os.environ["PATH_MATCHER_NAME"]
found = set()

for hr in data.get("hostRules", []):
    if domain in hr.get("hosts", []) and hr.get("pathMatcher"):
        found.add(hr["pathMatcher"])

for pm in data.get("pathMatchers", []):
    name = pm.get("name", "")
    default_svc = pm.get("defaultService", "")
    if name == default_pm or default_svc.endswith("/" + backend):
        found.add(name)

for name in sorted(found):
    print(name)
'
  )"

  if [[ -z "${MATCHERS_TO_REMOVE}" ]]; then
    echo "    No path matchers referencing '${DEMO_DOMAIN}' or '${BACKEND_SERVICE_NAME}' found on '${XLB_URL_MAP}'."
  else
    while IFS= read -r pm_name; do
      [[ -z "${pm_name}" ]] && continue
      echo "    Removing path matcher '${pm_name}' from '${XLB_URL_MAP}'..."
      gcloud compute url-maps remove-path-matcher "${XLB_URL_MAP}" \
        --path-matcher-name="${pm_name}" \
        --global \
        --project="${PROJECT_ID}" \
        --quiet
    done <<< "${MATCHERS_TO_REMOVE}"
  fi

  echo "[4] Deleting global backend service '${BACKEND_SERVICE_NAME}' (if present)..."
  if gcloud compute backend-services describe "${BACKEND_SERVICE_NAME}" --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud compute backend-services delete "${BACKEND_SERVICE_NAME}" \
      --global \
      --project="${PROJECT_ID}" \
      --quiet
  else
    echo "    Backend service '${BACKEND_SERVICE_NAME}' not found (already deleted)."
  fi

  echo "[5] Deleting Serverless NEG '${NEG_NAME}' in '${REGION}' (if present)..."
  if gcloud compute network-endpoint-groups describe "${NEG_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud compute network-endpoint-groups delete "${NEG_NAME}" \
      --region="${REGION}" \
      --project="${PROJECT_ID}" \
      --quiet
  else
    echo "    Serverless NEG '${NEG_NAME}' not found (already deleted)."
  fi

  echo "[6] Deleting Cloud Run service '${SERVICE_NAME}' in '${REGION}' (if present)..."
  if gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud run services delete "${SERVICE_NAME}" \
      --region="${REGION}" \
      --project="${PROJECT_ID}" \
      --quiet
  else
    echo "    Cloud Run service '${SERVICE_NAME}' not found (already deleted)."
  fi
fi

echo "[+] Cleanup (${MODE}) completed successfully."
