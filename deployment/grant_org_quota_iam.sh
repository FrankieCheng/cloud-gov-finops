#!/usr/bin/env bash
# Grant read-only Organization-level Quota & Project Discovery IAM roles
# for `cloud-gov-finops-agent` on `organizations/123456789012`.
#
# Run as an Organization Administrator (e.g. `admin@your-org.example.com`):
#   gcloud auth login admin@your-org.example.com
#   ORG_ADMIN_ACCOUNT=admin@your-org.example.com bash deployment/grant_org_quota_iam.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

PROJECT="${PROJECT:-${GOOGLE_CLOUD_PROJECT:-demo-core-prod}}"
ORG_ID="${ORG_ID:-${GOV_ORG_ID:-123456789012}}"
RUNTIME_SA="${RUNTIME_SA:-cloud-gov-finops-run@${PROJECT}.iam.gserviceaccount.com}"
ORG_ADMIN_ACCOUNT="${ORG_ADMIN_ACCOUNT:-}"

ACCOUNT_ARGS=()
if [[ -n "${ORG_ADMIN_ACCOUNT}" ]]; then
  ACCOUNT_ARGS=(--account="${ORG_ADMIN_ACCOUNT}")
fi

for ORG_ROLE in \
  roles/cloudquotas.viewer \
  roles/compute.viewer \
  roles/monitoring.viewer \
  roles/iam.securityReviewer \
  roles/browser \
  roles/resourcemanager.folderViewer; do
  echo "Granting ${ORG_ROLE} on organizations/${ORG_ID} to ${RUNTIME_SA}..."
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="${ORG_ROLE}" \
    --condition=None \
    "${ACCOUNT_ARGS[@]}" \
    --quiet >/dev/null
done

echo "Successfully granted read-only Organization Quota & Discovery roles on organizations/${ORG_ID} to ${RUNTIME_SA}."
