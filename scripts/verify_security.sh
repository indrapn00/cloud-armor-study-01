#!/usr/bin/env bash
# Safe, non-weaponized security verification script for cloud-armor-study-01.
# Tests both Pre-Armor (baseline unprotected state) and Post-Armor (enforced state).
#
# Usage:
#   ./scripts/verify_security.sh --mode pre-armor
#   ./scripts/verify_security.sh --mode post-armor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

MODE="post-armor"
BURST_COUNT=18

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --cloud-run-url)
      CLOUD_RUN_URL="$2"
      shift 2
      ;;
    --domain)
      DEMO_DOMAIN="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: $0 [--mode pre-armor|post-armor] [--cloud-run-url URL] [--domain DOMAIN]"
      exit 1
      ;;
  esac
done

BASE_URL="https://${DEMO_DOMAIN}"

echo "================================================================================"
echo " Google Cloud Armor Defensive Study Verification Suite"
echo " Mode                 : ${MODE}"
echo " Timestamp (UTC)      : $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo " GCP Project          : ${PROJECT_ID}"
echo " Cloud Run Direct URL : ${CLOUD_RUN_URL}"
echo " XLB Public Endpoint  : ${BASE_URL} (${XLB_IP})"
echo " Security Policy      : ${SECURITY_POLICY_NAME}"
echo "================================================================================"
echo ""

run_check() {
  local test_id="$1"
  local title="$2"
  local expected="$3"
  shift 3
  local tmp_body
  tmp_body="$(mktemp)"
  local http_code
  http_code="$(curl -sS -o "${tmp_body}" -w "%{http_code}" "$@" || echo "000")"
  echo "--------------------------------------------------------------------------------"
  echo "[${test_id}] ${title}"
  echo "  Expected (${MODE}) : ${expected}"
  echo "  Actual HTTP Status : HTTP ${http_code}"
  echo "  Response Preview   : $(head -c 260 "${tmp_body}" | tr '\n' ' ')"
  echo ""
  rm -f "${tmp_body}"
}

if [[ "${MODE}" == "pre-armor" ]]; then
  EXP_DIRECT="HTTP 403/404 (Blocked by Cloud Run internal-and-cloud-load-balancing ingress; GFE returns 404 on internal-route Cloudtop)"
  EXP_BASELINE="HTTP 200 (Interactive Browser Study Portal HTML via gcp2-xlb)"
  EXP_VALID_LOGIN="HTTP 200 (Enters Next Page /portal/dashboard as demo_user)"
  EXP_SQLI_LOGIN="HTTP 200 (VULNERABLE! SQLi Auth Bypass enters Next Page /portal/dashboard as admin)"
  EXP_XSS_SEARCH="HTTP 200 (VULNERABLE! Reflected <script> vector reaches Cloud Run origin)"
  EXP_LFI_VIEWER="HTTP 200 (VULNERABLE! Path traversal ../../../../etc/passwd reaches Cloud Run origin)"
  EXP_ADMIN_NO_AUTH="HTTP 200 (EXPOSED! Unprotected admin endpoint without Cloud Armor)"
  EXP_ADMIN_AUTH="HTTP 200 (Allowed with X-Admin-Token header)"
  EXP_HEADER_MARKER="HTTP 200 (UNFILTERED! Marker header X-Policy-Test: block-me reaches origin)"
  EXP_QUERY_MARKER="HTTP 200 (UNFILTERED! Query ?policy_test=block reaches origin)"
  EXP_BURST="All ${BURST_COUNT}/${BURST_COUNT} requests return HTTP 200 (UNTHROTTLED!)"
else
  EXP_DIRECT="HTTP 403/404 (Blocked by Cloud Run internal-and-cloud-load-balancing ingress; GFE returns 404 on internal-route Cloudtop)"
  EXP_BASELINE="HTTP 200 (Interactive Browser Study Portal HTML via gcp2-xlb)"
  EXP_VALID_LOGIN="HTTP 200 (Allowed by Cloud Armor -> enters Next Page /portal/dashboard as demo_user)"
  EXP_SQLI_LOGIN="HTTP 403 (BLOCKED at edge by Cloud Armor OWASP SQLi Rule Priority 2000 sqli-v33-stable)"
  EXP_XSS_SEARCH="HTTP 403 (BLOCKED at edge by Cloud Armor OWASP XSS Rule Priority 2000 xss-v33-stable)"
  EXP_LFI_VIEWER="HTTP 403 (BLOCKED at edge by Cloud Armor OWASP LFI Rule Priority 2100 lfi-v33-stable)"
  EXP_ADMIN_NO_AUTH="HTTP 403 (BLOCKED at edge by Cloud Armor Custom CEL Rule Priority 1000)"
  EXP_ADMIN_AUTH="HTTP 200 (Allowed by Cloud Armor when valid X-Admin-Token is present)"
  EXP_HEADER_MARKER="HTTP 403 (BLOCKED at edge by Cloud Armor Custom CEL Rule Priority 1100)"
  EXP_QUERY_MARKER="HTTP 403 (BLOCKED at edge by Cloud Armor Custom CEL Rule Priority 1100)"
  EXP_BURST="First <=10 requests HTTP 200, excess requests throttled with HTTP 429 (Rule Priority 3000)"
fi

# Test 1: Direct Cloud Run .run.app URL (Origin Bypass Prevention)
run_check "TEST 1" \
  "Direct Cloud Run Default URL (${CLOUD_RUN_URL}/)" \
  "${EXP_DIRECT}" \
  "${CLOUD_RUN_URL}/"

# Test 2: Legitimate Baseline Request via XLB (Browser Portal HTML)
run_check "TEST 2" \
  "Interactive Browser Study Portal (GET ${BASE_URL}/)" \
  "${EXP_BASELINE}" \
  "${BASE_URL}/"

# Test 2B: Valid Login Form Submission -> Next Page (/portal/dashboard)
run_check "TEST 2B" \
  "Valid Browser Login Submission (POST ${BASE_URL}/login -> demo_user)" \
  "${EXP_VALID_LOGIN}" \
  -X POST \
  -d "username=demo_user&password=CloudArmor2026!" \
  "${BASE_URL}/login"

# Test 2C: SQL Injection Login Bypass Submission -> Next Page vs HTTP 403 Block
run_check "TEST 2C-1" \
  "SQLi Auth Bypass Login Submission (POST ${BASE_URL}/login -> admin' OR '1'='1)" \
  "${EXP_SQLI_LOGIN}" \
  -X POST \
  --data-urlencode "username=admin' OR '1'='1" \
  --data-urlencode "password=anything" \
  "${BASE_URL}/login"

# Test 2C-2: SQL Injection Comment Bypass Submission -> Next Page vs HTTP 403 Block
run_check "TEST 2C-2" \
  "SQLi Comment Bypass Login Submission (POST ${BASE_URL}/login -> admin' -- )" \
  "${EXP_SQLI_LOGIN}" \
  -X POST \
  --data-urlencode "username=admin' -- " \
  --data-urlencode "password=ignored" \
  "${BASE_URL}/login"

# Test 2D: Reflected XSS Search Form Submission
run_check "TEST 2D" \
  "Browser Search XSS Test (GET ${BASE_URL}/search?q=<script>alert(1)</script>)" \
  "${EXP_XSS_SEARCH}" \
  -G \
  --data-urlencode "q=<script>alert(1)</script>" \
  "${BASE_URL}/search"

# Test 2E: LFI Path Traversal Document Viewer Submission
run_check "TEST 2E" \
  "Browser Document Viewer LFI Test (GET ${BASE_URL}/viewer?doc=../../../../etc/passwd)" \
  "${EXP_LFI_VIEWER}" \
  -G \
  --data-urlencode "doc=../../../../etc/passwd" \
  "${BASE_URL}/viewer"

# Test 3: Unprotected /admin/diagnostics WITHOUT X-Admin-Token header
run_check "TEST 3" \
  "Admin Diagnostics WITHOUT Auth Header (GET ${BASE_URL}/admin/diagnostics)" \
  "${EXP_ADMIN_NO_AUTH}" \
  "${BASE_URL}/admin/diagnostics"

# Test 4: Authorized /admin/diagnostics WITH valid X-Admin-Token header
run_check "TEST 4" \
  "Admin Diagnostics WITH Valid X-Admin-Token Header (GET ${BASE_URL}/admin/diagnostics)" \
  "${EXP_ADMIN_AUTH}" \
  -H "X-Admin-Token: ${ADMIN_HEADER_TOKEN}" \
  "${BASE_URL}/admin/diagnostics"

# Test 5A: Custom CEL Policy Verification Marker in Header
run_check "TEST 5A" \
  "Inspect Endpoint WITH Benign Test Header 'X-Policy-Test: block-me'" \
  "${EXP_HEADER_MARKER}" \
  -H "X-Policy-Test: block-me" \
  "${BASE_URL}/api/inspect"

# Test 5B: Custom CEL Policy Verification Marker in Query Parameter
run_check "TEST 5B" \
  "Inspect Endpoint WITH Benign Test Query '?policy_test=block'" \
  "${EXP_QUERY_MARKER}" \
  "${BASE_URL}/api/inspect?policy_test=block"

# Test 6: Rapid Burst Rate-Limit Check on /api/ping
echo "--------------------------------------------------------------------------------"
echo "[TEST 6] Rapid Burst Rate-Limit Check (${BURST_COUNT} requests to ${BASE_URL}/api/ping)"
echo "  Expected (${MODE}) : ${EXP_BURST}"
ok_count=0
throttled_count=0
other_count=0
status_sequence=""

for i in $(seq 1 "${BURST_COUNT}"); do
  code="$(curl -sS -o /dev/null -w "%{http_code}" "${BASE_URL}/api/ping" || echo "000")"
  status_sequence="${status_sequence} ${code}"
  if [[ "${code}" == "200" ]]; then
    ok_count=$((ok_count + 1))
  elif [[ "${code}" == "429" || "${code}" == "403" ]]; then
    throttled_count=$((throttled_count + 1))
  else
    other_count=$((other_count + 1))
  fi
done

echo "  Status Sequence    :${status_sequence}"
echo "  Burst Summary      : HTTP 200 = ${ok_count}/${BURST_COUNT} | Throttled (HTTP 429) = ${throttled_count}/${BURST_COUNT} | Other = ${other_count}/${BURST_COUNT}"
echo "================================================================================"
