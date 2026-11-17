# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Architectural FinOps Optimizer (Network Egress, Intra-Org VPN, Armor/LB Overhead & BQ Job Culprits)."""

from __future__ import annotations

import datetime
import logging
from collections import defaultdict
from typing import Any

from billing.analyzer import BILLING_ACCOUNT_BUCKET, _make_bq_client
from bot import config

logger = logging.getLogger(__name__)


def analyze_architecture_and_bq_finops(
    tables: list[str] | None = None,
    lookback_days: int = 14,
) -> dict[str, Any]:
    """Audit 14-day Network/Fixed-Hourly Architectural Overhead & BigQuery Heavy-Job Culprits."""
    eff_days = max(7, min(int(lookback_days), 30))
    scale_to_month = 30.0 / float(eff_days)

    if config.get_api_mode() == "MOCK":
        return {
            "mode": "MOCK",
            "lookback_days": eff_days,
            "network_category_spend_usd": {
                "VPN_HYBRID": 70.76,
                "NETWORK_SECURITY_ARMOR_DNS": 34.84,
                "LOAD_BALANCING_PSC": 21.17,
                "INTERNET_AND_CROSS_REGION_EGRESS": 6.40,
            },
            "estimated_monthly_arch_savings_usd": 174.50,
            "architectural_recommendations": [
                {
                    "category": "INTRA_ORG_VPN_TO_PEERING",
                    "projects": ["demo-net-hub-a", "demo-net-hub-b"],
                    "current_monthly_run_rate_usd": 151.63,
                    "estimated_monthly_savings_usd": 151.63,
                    "summary": (
                        "检测到同一组织内项目 `demo-net-hub-a` 与 `demo-net-hub-b` 之间通过计费 HA Cloud VPN 互联（折算约 $151.63/月）；"
                        "若非模拟混合云实验，改用同组织免费 **VPC Network Peering / Shared VPC** 可节省 100% 隧道固定小时费。"
                    ),
                },
                {
                    "category": "SECURITY_POLICY_CONSOLIDATION",
                    "projects": ["demo-core-prod", "demo-edge-svc"],
                    "current_monthly_run_rate_usd": 74.66,
                    "estimated_monthly_savings_usd": 22.87,
                    "summary": (
                        "检测到多套 Cloud Armor 策略与 DNS Armor 高级威胁检测固定订阅费（折算约 $74.66/月）；"
                        "建议合并非生产测试项目的重复 Armor Policy。"
                    ),
                },
            ],
            "bigquery_heavy_jobs": [
                {
                    "project_id": "demo-core-prod",
                    "region": "region-us",
                    "user_email": "etl-runner@demo-core-prod.iam.gserviceaccount.com",
                    "job_id": "bquxjob_7f12a89_mock",
                    "tb_billed": 21.46,
                    "estimated_cost_usd": 134.13,
                    "query_preview": "SELECT * FROM `public-events.raw_logs` WHERE event_type = 'click'",
                }
            ],
            "bigquery_job_audit_note": "",
        }

    from google.cloud import bigquery

    validated_tables = [
        config.validate_bq_table_id(t) for t in (tables or config.get_billing_export_tables())
    ]
    part_start = (
        datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(days=eff_days + 1)
    ).isoformat()
    start_day = (
        datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(days=eff_days)
    ).isoformat()

    branches = " UNION ALL ".join(
        f"""
        SELECT
          DATE(usage_start_time, @tz) AS u_day,
          IFNULL(project.id, @acct_bucket) AS pid,
          IFNULL(service.description, '') AS svc,
          IFNULL(sku.description, '') AS sku,
          cost + IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0.0) AS net_cost
        FROM `{tbl}`
        WHERE _PARTITIONTIME >= TIMESTAMP(@part_start)
        """
        for tbl in validated_tables
    )
    sql = f"""
    SELECT
      pid,
      svc,
      sku,
      ROUND(SUM(net_cost), 4) AS net_spend
    FROM ({branches})
    WHERE u_day >= DATE(@start_day)
      AND (
        LOWER(svc) LIKE '%network%'
        OR LOWER(sku) LIKE '%egress%'
        OR LOWER(sku) LIKE '%data transfer%'
        OR LOWER(sku) LIKE '%vpn%'
        OR LOWER(sku) LIKE '%nat%'
        OR LOWER(sku) LIKE '%armor%'
        OR LOWER(sku) LIKE '%forwarding rule%'
        OR LOWER(sku) LIKE '%private service connect%'
        OR (LOWER(svc) = 'cloud run' AND LOWER(sku) LIKE '%allocation time%')
      )
    GROUP BY 1, 2, 3
    HAVING net_spend >= 0.20
    ORDER BY net_spend DESC
    """
    client = _make_bq_client()
    rows = list(
        client.query(
            sql,
            job_config=bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("part_start", "STRING", part_start),
                    bigquery.ScalarQueryParameter("start_day", "STRING", start_day),
                    bigquery.ScalarQueryParameter("tz", "STRING", config.get_billing_timezone()),
                    bigquery.ScalarQueryParameter("acct_bucket", "STRING", BILLING_ACCOUNT_BUCKET),
                ]
            ),
        ).result()
    )

    cat_spend: dict[str, float] = {
        "VPN_HYBRID": 0.0,
        "NETWORK_SECURITY_ARMOR_DNS": 0.0,
        "LOAD_BALANCING_PSC_NAT": 0.0,
        "INTERNET_AND_CROSS_REGION_EGRESS": 0.0,
        "CLOUD_RUN_ALWAYS_ON_ALLOCATION": 0.0,
    }
    vpn_by_proj: dict[str, float] = defaultdict(float)
    armor_by_proj: dict[str, float] = defaultdict(float)
    lb_psc_by_proj: dict[str, float] = defaultdict(float)
    crun_by_proj: dict[str, float] = defaultdict(float)

    for r in rows:
        pid = str(r["pid"])
        svc_l = str(r["svc"]).lower()
        sku_l = str(r["sku"]).lower()
        amt = float(r["net_spend"] or 0.0)

        if "cloud run" in svc_l:
            cat_spend["CLOUD_RUN_ALWAYS_ON_ALLOCATION"] += amt
            crun_by_proj[pid] += amt
        elif "vpn" in sku_l or "interconnect" in sku_l:
            cat_spend["VPN_HYBRID"] += amt
            vpn_by_proj[pid] += amt
        elif "armor" in sku_l or "network security" in svc_l:
            cat_spend["NETWORK_SECURITY_ARMOR_DNS"] += amt
            armor_by_proj[pid] += amt
        elif any(k in sku_l for k in ("forwarding rule", "private service connect", "nat gateway")):
            cat_spend["LOAD_BALANCING_PSC_NAT"] += amt
            lb_psc_by_proj[pid] += amt
        else:
            cat_spend["INTERNET_AND_CROSS_REGION_EGRESS"] += amt

    recs: list[dict[str, Any]] = []
    if vpn_by_proj:
        vpn_monthly = round(sum(vpn_by_proj.values()) * scale_to_month, 2)
        projs = sorted(vpn_by_proj.keys())
        est_save = round(vpn_monthly * (1.0 if len(projs) >= 2 else 0.5), 2)
        recs.append(
            {
                "category": "INTRA_ORG_VPN_TO_PEERING",
                "projects": projs,
                "current_monthly_run_rate_usd": vpn_monthly,
                "estimated_monthly_savings_usd": est_save,
                "summary": (
                    f"项目 `{', '.join(projs)}` 正在承担 Cloud VPN 隧道固定小时费（折算约 **${vpn_monthly:.2f}/月**）；"
                    "若属于同组织跨项目互通（而非连回线下 IDC），切换为 **VPC Network Peering 或 Shared VPC** 可省去隧道租用费。"
                ),
            }
        )

    if armor_by_proj:
        armor_monthly = round(sum(armor_by_proj.values()) * scale_to_month, 2)
        if armor_monthly >= 10.0:
            projs = sorted(armor_by_proj.keys())
            recs.append(
                {
                    "category": "SECURITY_POLICY_CONSOLIDATION",
                    "projects": projs,
                    "current_monthly_run_rate_usd": armor_monthly,
                    "estimated_monthly_savings_usd": round(armor_monthly * 0.35, 2),
                    "summary": (
                        f"项目 `{', '.join(projs)}` 上启用了 Cloud Armor / DNS Armor 高级策略（折算固定月费约 **${armor_monthly:.2f}/月**）；"
                        "建议排查非生产测试环境是否存在闲置安全策略或 DNS Armor 测试订阅。"
                    ),
                }
            )

    if lb_psc_by_proj:
        lb_monthly = round(sum(lb_psc_by_proj.values()) * scale_to_month, 2)
        if lb_monthly >= 15.0:
            projs = sorted(lb_psc_by_proj.keys())
            recs.append(
                {
                    "category": "LB_PSC_FORWARDING_CONSOLIDATION",
                    "projects": projs,
                    "current_monthly_run_rate_usd": lb_monthly,
                    "estimated_monthly_savings_usd": round(lb_monthly * 0.30, 2),
                    "summary": (
                        f"负载均衡最小转发规则与 PSC 端点固定开销折算约 **${lb_monthly:.2f}/月**（`{', '.join(projs)}`）；"
                        "多域名 HTTP(S) 服务建议共用单一全局 ALB URL Map 路由。"
                    ),
                }
            )

    if crun_by_proj:
        crun_monthly = round(sum(crun_by_proj.values()) * scale_to_month, 2)
        if crun_monthly >= 25.0:
            projs = sorted(crun_by_proj.keys())
            recs.append(
                {
                    "category": "CLOUD_RUN_MIN_INSTANCES_REVIEW",
                    "projects": projs,
                    "current_monthly_run_rate_usd": crun_monthly,
                    "estimated_monthly_savings_usd": round(crun_monthly * 0.25, 2),
                    "summary": (
                        f"Cloud Run 常驻实例 (`min-instances`) 资源分配折算约 **${crun_monthly:.2f}/月**；"
                        "除需维持飞书 WebSocket 长连接的 Bot 服务外，纯 HTTP 门户建议设为 `min-instances=0` 按请求计费。"
                    ),
                }
            )

    # Probe BigQuery INFORMATION_SCHEMA.JOBS_BY_PROJECT for heavy SQL culprits (>10 GB billed)
    bq_proj = config.get_billing_bq_project()
    heavy_jobs: list[dict[str, Any]] = []
    bq_note = ""
    for reg in ("region-us", "region-us-central1"):
        try:
            j_sql = f"""
            SELECT
              user_email,
              job_id,
              ROUND(total_bytes_billed / POW(1024, 4), 4) AS tb_billed,
              ROUND((total_bytes_billed / POW(1024, 4)) * 6.25, 2) AS est_usd,
              SUBSTR(REGEXP_REPLACE(IFNULL(query, ''), r'\\s+', ' '), 1, 140) AS q_snip
            FROM `{bq_proj}`.`{reg}`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
            WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
              AND total_bytes_billed >= 10737418240
            ORDER BY total_bytes_billed DESC
            LIMIT 5
            """
            for jr in client.query(j_sql).result():
                heavy_jobs.append(
                    {
                        "project_id": bq_proj,
                        "region": reg,
                        "user_email": str(jr["user_email"] or ""),
                        "job_id": str(jr["job_id"] or ""),
                        "tb_billed": float(jr["tb_billed"] or 0.0),
                        "estimated_cost_usd": float(jr["est_usd"] or 0.0),
                        "query_preview": str(jr["q_snip"] or ""),
                    }
                )
        except Exception as exc:
            if "403" in str(exc) or "Access Denied" in str(exc):
                bq_note = (
                    f"如需下钻定位单条高价 BigQuery SQL 的执行人 (`user_email`) 与 `job_id`，"
                    f"请为运行服务账号补充只读元数据角色 `roles/bigquery.resourceViewer`："
                    f"`gcloud projects add-iam-policy-binding {bq_proj} --member=serviceAccount:<RUNTIME_SA> --role=roles/bigquery.resourceViewer --condition=None`"
                )

    return {
        "mode": "LIVE",
        "lookback_days": eff_days,
        "network_category_spend_usd": {k: round(v, 2) for k, v in cat_spend.items()},
        "estimated_monthly_arch_savings_usd": round(
            sum(float(x["estimated_monthly_savings_usd"]) for x in recs), 2
        ),
        "architectural_recommendations": recs,
        "bigquery_heavy_jobs": heavy_jobs,
        "bigquery_job_audit_note": bq_note,
    }


def build_architecture_finops_feishu_card(report: dict[str, Any]) -> dict[str, Any]:
    """Render Feishu interactive card for Network & Architectural Cost Optimization + BQ SQL Culprits."""
    sav = float(report.get("estimated_monthly_arch_savings_usd") or 0.0)
    recs = list(report.get("architectural_recommendations") or [])
    cats = report.get("network_category_spend_usd") or {}
    jobs = list(report.get("bigquery_heavy_jobs") or [])
    days = int(report.get("lookback_days") or 14)

    template = "orange" if sav >= 20.0 or jobs else "blue"
    title = f"🏗️ 云架构级固定成本优化与网络/BigQuery 深潜（预计可优 ${sav:.2f}/月）"

    overview = (
        f"近 {days} 天网络与常驻架构支出拆解:\n"
        f"• VPN / 混合云隧道: ${cats.get('VPN_HYBRID', 0.0):.2f} | "
        f"安全策略 (Cloud/DNS Armor): ${cats.get('NETWORK_SECURITY_ARMOR_DNS', 0.0):.2f}\n"
        f"• 负载均衡转发规则 / PSC: ${cats.get('LOAD_BALANCING_PSC_NAT', cats.get('LOAD_BALANCING_PSC', 0.0)):.2f} | "
        f"公网与跨区流量 (Egress): ${cats.get('INTERNET_AND_CROSS_REGION_EGRESS', 0.0):.2f}"
    )
    elements: list[dict[str, Any]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": overview}},
        {"tag": "hr"},
    ]

    sections: list[str] = []
    if recs:
        r_lines = [f"【💡 架构级降本建议 ({len(recs)} 项 · 潜在优化空间 ${sav:.2f}/月)】"]
        for r in recs[:5]:
            r_lines.append(
                f"• [{r.get('category')}] 当前月化 ${r.get('current_monthly_run_rate_usd', 0.0):.2f}/月 "
                f"(预计可省 ${r.get('estimated_monthly_savings_usd', 0.0):.2f}/月)\n"
                f"  ↳ {r.get('summary')}"
            )
        sections.append("\n".join(r_lines))

    if jobs:
        j_lines = ["【🔍 近 30 天高消耗 BigQuery 按需扫描任务归因 (>10 GB)】"]
        for j in jobs[:5]:
            j_lines.append(
                f"• [{j.get('project_id')} | {j.get('region')}] {j.get('user_email')} (`{j.get('job_id')}`): "
                f"{j.get('tb_billed')} TB (约 ${j.get('estimated_cost_usd'):.2f})\n"
                f"  ↳ SQL: {j.get('query_preview')}"
            )
        sections.append("\n".join(j_lines))
    elif report.get("bigquery_job_audit_note"):
        sections.append(f"【ℹ️ BigQuery SQL 任务级归因提示】\n{report.get('bigquery_job_audit_note')}")

    elements.append(
        {"tag": "div", "text": {"tag": "plain_text", "content": "\n\n".join(sections)[:3800]}}
    )
    return {
        "config": {"wide_screen_mode": True},
        "header": {"template": template, "title": {"tag": "plain_text", "content": title}},
        "elements": elements,
    }
