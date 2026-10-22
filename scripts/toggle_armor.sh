#!/usr/bin/env bash
# Helper script to attach, detach, or check the Cloud Armor security policy
# on the Cloud Run backend service (`cloud-armor-demo-backend-svc`).
#
# Usage:
#   ./scripts/toggle_armor.sh attach
#   ./scripts/toggle_armor.sh detach
#   ./scripts/toggle_armor.sh status

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

ACTION="${1:-status}"

case "${ACTION}" in
  attach)
    echo "[*] Attaching Cloud Armor policy '${SECURITY_POLICY_NAME}' to backend service '${BACKEND_SERVICE_NAME}'..."
    gcloud compute backend-services update "${BACKEND_SERVICE_NAME}" \
      --global \
      --security-policy="${SECURITY_POLICY_NAME}" \
      --project="${PROJECT_ID}" \
      --quiet
    echo "[+] Policy attached. Note: Edge propagation typically takes 30-60 seconds."
    ;;
  detach)
    echo "[*] Detaching Cloud Armor policy from backend service '${BACKEND_SERVICE_NAME}'..."
    gcloud compute backend-services update "${BACKEND_SERVICE_NAME}" \
      --global \
      --security-policy="" \
      --project="${PROJECT_ID}" \
      --quiet
    echo "[+] Policy detached (backend service is now unprotected at the L7 edge)."
    ;;
  status)
    echo "[*] Checking active securityPolicy on '${BACKEND_SERVICE_NAME}':"
    gcloud compute backend-services describe "${BACKEND_SERVICE_NAME}" \
      --global \
      --project="${PROJECT_ID}" \
      --format="yaml(name,securityPolicy,backends)"
    ;;
  *)
    echo "Usage: $0 {attach|detach|status}"
    exit 1
    ;;
esac
