#!/usr/bin/env bash
# Deploy standalone Cloud Governance & FinOps Feishu Bot (`cloud-gov-finops-agent`) to Cloud Run.
#
# Mounts dedicated Feishu Webhook secrets (`FEISHU_GOV_WEBHOOK_URL`, `FEISHU_GOV_WEBHOOK_SECRET`)
# and/or App Bot secrets (`FEISHU_GOV_APP_ID`, `FEISHU_GOV_APP_SECRET`) from Secret Manager,
# keeping this service completely isolated from `cloud-case-agent`.
set -euo pipefail

cd "$(dirname "$0")/.."
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

PROJECT="${PROJECT:-demo-core-prod}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-cloud-gov-finops-agent}"
RUNTIME_SA="${RUNTIME_SA:-cloud-gov-finops-run@${PROJECT}.iam.gserviceaccount.com}"

GOV_ORG_ID="${GOV_ORG_ID:-123456789012}"
GOV_PROJECTS="${GOV_PROJECTS:-demo-core-prod,demo-edge-svc,demo-net-hub-a,demo-net-hub-b,demo-shared-dns}"
BILLING_BQ_PROJECT="${BILLING_BQ_PROJECT:-demo-core-prod}"
BILLING_EXPORT_TABLES="${BILLING_EXPORT_TABLES:-demo-core-prod.billing.gcp_billing_export_resource_v1_01ABCD_EF0123_456789}"
GOV_AGENT_MODEL="${GOV_AGENT_MODEL:-gemini-4-hydrogen}"
PATROL_INTERVAL_SECONDS="${PATROL_INTERVAL_SECONDS:-86400}"
PATROL_DAILY_HOUR="${PATROL_DAILY_HOUR:-9}"
PATROL_DEFAULT_SCOPE="${PATROL_DEFAULT_SCOPE:-EXECUTIVE}"
BILLING_MONTHLY_BUDGET_USD="${BILLING_MONTHLY_BUDGET_USD:-1200}"
GOV_STATE_GCS_BUCKET="${GOV_STATE_GCS_BUCKET:-demo-gov-state-bucket}"

SECRETS="SESSION_SECRET_KEY=SESSION_SECRET_KEY:latest"

if gcloud secrets describe FEISHU_GOV_WEBHOOK_URL --project "${PROJECT}" >/dev/null 2>&1; then
  SECRETS="${SECRETS},FEISHU_GOV_WEBHOOK_URL=FEISHU_GOV_WEBHOOK_URL:latest"
  echo "Found FEISHU_GOV_WEBHOOK_URL in Secret Manager: enabling signed Feishu Webhook patrol delivery."
fi

if gcloud secrets describe FEISHU_GOV_WEBHOOK_SECRET --project "${PROJECT}" >/dev/null 2>&1; then
  SECRETS="${SECRETS},FEISHU_GOV_WEBHOOK_SECRET=FEISHU_GOV_WEBHOOK_SECRET:latest"
  echo "Found FEISHU_GOV_WEBHOOK_SECRET in Secret Manager: enabling HMAC-SHA256 webhook signature."
fi

if gcloud secrets describe FEISHU_GOV_APP_ID --project "${PROJECT}" >/dev/null 2>&1 \
  && gcloud secrets describe FEISHU_GOV_APP_SECRET --project "${PROJECT}" >/dev/null 2>&1; then
  SECRETS="${SECRETS},FEISHU_GOV_APP_ID=FEISHU_GOV_APP_ID:latest,FEISHU_GOV_APP_SECRET=FEISHU_GOV_APP_SECRET:latest"
  echo "Found FEISHU_GOV_APP_ID / FEISHU_GOV_APP_SECRET: enabling interactive GovFeishuBot WebSocket."
fi

gcloud beta run deploy "${SERVICE}" \
  --project "${PROJECT}" --region "${REGION}" --source . \
  --memory 2Gi --cpu 1 --min-instances 1 --max-instances 1 --concurrency 8 \
  --no-allow-unauthenticated --no-cpu-throttling --iap \
  --service-account "${RUNTIME_SA}" \
  --update-env-vars "^:^GOV_API_MODE=LIVE:CHAT_ENGINE=llm:GOV_AGENT_MODEL=${GOV_AGENT_MODEL}:GOV_ORG_ID=${GOV_ORG_ID}:GOV_PROJECTS=${GOV_PROJECTS}:BILLING_BQ_PROJECT=${BILLING_BQ_PROJECT}:BILLING_EXPORT_TABLES=${BILLING_EXPORT_TABLES}:BILLING_MONTHLY_BUDGET_USD=${BILLING_MONTHLY_BUDGET_USD}:GOV_STATE_GCS_BUCKET=${GOV_STATE_GCS_BUCKET}:PATROL_INTERVAL_SECONDS=${PATROL_INTERVAL_SECONDS}:PATROL_DAILY_HOUR=${PATROL_DAILY_HOUR}:PATROL_DEFAULT_SCOPE=${PATROL_DEFAULT_SCOPE}:GOOGLE_CLOUD_PROJECT=${PROJECT}:GOOGLE_CLOUD_LOCATION=global:GOOGLE_GENAI_USE_VERTEXAI=true" \
  --update-secrets "${SECRETS}" \
  --labels created-by=agents-cli \
  --quiet
