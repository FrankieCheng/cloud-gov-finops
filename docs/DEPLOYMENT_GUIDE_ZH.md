# GCP 云管与 FinOps 账单飞书机器人 — 部署指南

本文档说明如何配置并部署独立的 **云管与账单异常监控服务 (`cloud-gov-finops-agent`)** 及对应的新飞书机器人（默认搭载 Vertex AI 最新 Gemini 4 系列高速智能体模型 **`gemini-4-hydrogen`**，端点区域固定为 `GOOGLE_CLOUD_LOCATION=global`，亦可按需通过 `GOV_AGENT_MODEL` 切换为 `gemini-4-argon` 或 `gemini-4-carbon`）。

---

## 1. GCP 服务账号与权限配置（Project 级 + Org 级 + Billing 表）

本服务需要读取 **BigQuery 账单导出表**、**各业务项目配额/监控指标** 以及 **组织级 Cloud Quotas**：

```bash
export PROJECT_ID="demo-core-prod"
export ORG_ID="123456789012"
export RUNTIME_SA_NAME="cloud-gov-finops-run"
export RUNTIME_SA="${RUNTIME_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# 1. 创建独立运行时服务账号
gcloud iam service-accounts create "${RUNTIME_SA_NAME}" \
  --display-name="Cloud Governance & FinOps Bot SA" \
  --project="${PROJECT_ID}"

# 2. 宿主项目权限：Vertex AI 模型调用 + BigQuery 作业执行/账单读取/SQL任务元数据归因 + 日志
for ROLE in \
  roles/aiplatform.user \
  roles/bigquery.jobUser \
  roles/bigquery.dataViewer \
  roles/bigquery.resourceViewer \
  roles/compute.viewer \
  roles/monitoring.viewer \
  roles/cloudquotas.viewer \
  roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="${ROLE}" \
    --condition=None
done

# 3. 组织级（Org 级）配额与项目发现权限（强烈推荐，支持自动扫描组织下全部子项目与组织级配额）
for ORG_ROLE in \
  roles/resourcemanager.folderViewer \
  roles/browser \
  roles/compute.viewer \
  roles/monitoring.viewer \
  roles/cloudquotas.viewer; do
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="${ORG_ROLE}"
done
```

> **优雅降级说明**：若暂时只授予了部分项目的 `compute.viewer` / `monitoring.viewer`，未授予组织级 `roles/cloudquotas.viewer`，系统仍会正常完成已授权项目的配额与全组织账单扫描，并在飞书卡片底部温和提示缺失权限的范围。

---

## 2. 配置飞书群签名 Webhook 或自建应用机器人（Secret Manager 隔离存储）

### 方式 A：飞书自定义机器人签名 Webhook（定时/主动巡检日报推送）

将飞书群自定义机器人的 **Webhook 地址** 与 **签名密钥（Signature Secret）** 存入 Secret Manager（严禁明文入库）：

```bash
printf "%s" "https://open.feishu.cn/open-apis/bot/v2/hook/<YOUR_HOOK_ID>" | \
  gcloud secrets create FEISHU_GOV_WEBHOOK_URL --data-file=- --project="${PROJECT_ID}"

printf "%s" "<YOUR_SIGNATURE_SECRET>" | \
  gcloud secrets create FEISHU_GOV_WEBHOOK_SECRET --data-file=- --project="${PROJECT_ID}"

for SEC in SESSION_SECRET_KEY FEISHU_GOV_WEBHOOK_URL FEISHU_GOV_WEBHOOK_SECRET; do
  gcloud secrets add-iam-policy-binding "${SEC}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}"
done
```

### 方式 B（可选叠加）：飞书企业自建应用双向交互 Bot

1. 登录 [飞书开放平台](https://open.feishu.cn/app) 新建独立自建应用（例如命名为 **「GCP 云管与账单雷达」**），开启 **机器人** 能力。
2. 在「权限管理」中开通：
   - `im:message`、`im:message.p2p_msg:readonly`、`im:message.group_at_msg:readonly`、`im:message.group_msg`
   - `im:resource`（用于直接在飞书上传最新 `.tsv`/`.csv` MSA 表格导入）
   - `im:chat:readonly`
3. 将新机器人的 **App ID** 与 **App Secret** 存入 Secret Manager（与工单机器人的 `FEISHU_APP_ID` 完全隔离）：

```bash
printf "%s" "cli_new_gov_app_id" | \
  gcloud secrets create FEISHU_GOV_APP_ID --data-file=- --project="${PROJECT_ID}"

printf "%s" "your_new_gov_app_secret" | \
  gcloud secrets create FEISHU_GOV_APP_SECRET --data-file=- --project="${PROJECT_ID}"

for SEC in FEISHU_GOV_APP_ID FEISHU_GOV_APP_SECRET; do
  gcloud secrets add-iam-policy-binding "${SEC}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}"
done
```

---

## 3. 组织级（Org）只读配额权限一键授权

使用组织管理员账号登录并执行 [grant_org_quota_iam.sh](../deployment/grant_org_quota_iam.sh)：

```bash
gcloud auth login admin@your-org.example.com
ORG_ADMIN_ACCOUNT=admin@your-org.example.com bash deployment/grant_org_quota_iam.sh
```

---

## 4. 一键部署至 Cloud Run

```bash
cd ~/cloud-gov-finops

# 默认每日北京时间 09:00 自动执行全量云管 (MSA + Quota) 与账单异常巡检并推送飞书卡片
PROJECT=demo-core-prod \
REGION=us-central1 \
GOV_AGENT_MODEL=gemini-4-hydrogen \
GOV_ORG_ID=123456789012 \
PATROL_DAILY_HOUR=9 \
BILLING_EXPORT_TABLES="demo-core-prod.billing.gcp_billing_export_resource_v1_01ABCD_EF0123_456789" \
bash deployment/deploy_gov_prod.sh
```
