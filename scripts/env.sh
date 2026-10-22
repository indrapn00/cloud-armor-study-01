#!/usr/bin/env bash
# Central configuration variables for cloud-armor-study-01
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

export PROJECT_ID="gcp-demo-02-307713"
export PROJECT_NUMBER="66063681189"
export REGION="asia-southeast2"

# Cloud Run service (deployed with --ingress=internal-and-cloud-load-balancing)
export SERVICE_NAME="cloud-armor-demo-service"
export CLOUD_RUN_URL="${CLOUD_RUN_URL:-https://cloud-armor-demo-service-66063681189.asia-southeast2.run.app}"

# External Application Load Balancer (existing XLB in gcp-demo-02-307713)
export XLB_URL_MAP="gcp2-xlb"
export XLB_IP="34.49.218.84"
export DEMO_DOMAIN="gcp2demo01.iphamsterviel.org"
export PATH_MATCHER_NAME="cloud-armor-demo-matcher"

# Serverless NEG & Backend Service for this demo
export NEG_NAME="cloud-armor-demo-neg"
export BACKEND_SERVICE_NAME="cloud-armor-demo-backend-svc"

# Google Cloud Armor Security Policy
export SECURITY_POLICY_NAME="cloud-armor-study-policy-01"
export ADMIN_HEADER_TOKEN="study-secret-2026"
