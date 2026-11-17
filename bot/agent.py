# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Google ADK Cloud Governance & FinOps Agent (`gemini-2.5-flash`) unifying msa/, quota/, and billing/."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from billing.architecture_advisor import build_architecture_finops_feishu_card
from billing.service import (
    build_billing_feishu_card,
    build_finops_governance_feishu_card,
    get_billing_service,
)
from bot.cache import invalidate_cache
from msa.service import build_msa_feishu_card, get_msa_service
from quota.hygiene import build_account_hygiene_feishu_card
from quota.service import build_quota_feishu_card, get_quota_service

logger = logging.getLogger(__name__)

MODEL = os.getenv("GOV_AGENT_MODEL", "gemini-2.5-flash")


def compute_executive_health_report(monthly_budget_usd: float = 0.0) -> dict[str, Any]:
    """Compute a 0-100 Enterprise Cloud Account & FinOps Health Scorecard across 5 governance pillars."""
    msa_svc = get_msa_service()
    try:
        msa_svc.auto_correlate_impacted_projects()
    except Exception as exc:
        logger.debug("MSA auto-correlation skipped during health score: %s", type(exc).__name__)
    msa_radar = msa_svc.get_governance_radar()
    quota_rep = get_quota_service().scan_all_cached(include_org=True)
    hygiene_rep = get_quota_service().audit_hygiene()
    daily_bill = get_billing_service().generate_daily_report_cached()
    finops_gov = get_billing_service().generate_finops_governance_report(
        monthly_budget_usd=monthly_budget_usd if monthly_budget_usd > 0 else None
    )

    # Pillar 1: Cost Stability & Budget Pacing (25 pts)
    p1 = 25
    if finops_gov.budget_status == "EXCEEDED":
        p1 -= 12
    elif finops_gov.budget_status == "WARNING":
        p1 -= 5
    p1 -= min(13, len(daily_bill.suspected_anomalies) * 4 + len(daily_bill.intraday_alerts) * 8)
    p1 = max(0, p1)

    # Pillar 2: Waste Elimination & Tag Hygiene (20 pts)
    p2 = 20
    if finops_gov.estimated_monthly_waste_usd >= 20.0:
        p2 -= 8
    elif finops_gov.estimated_monthly_waste_usd > 0:
        p2 -= 4
    if finops_gov.unlabeled_spend_pct >= 50.0:
        p2 -= 7
    elif finops_gov.unlabeled_spend_pct >= 25.0:
        p2 -= 3
    p2 = max(0, p2)

    # Pillar 3: Project & Org Quota Headroom (20 pts)
    p3 = 20
    p3 -= min(16, len(quota_rep.critical_over_90) * 8 + len(quota_rep.recent_exceeded_events) * 6)
    p3 -= min(4, len(quota_rep.warning_80_to_90) * 2)
    p3 = max(0, p3)

    # Pillar 4: IAM, Key & Firewall Security Hygiene (20 pts)
    p4 = 20
    p4 -= min(10, hygiene_rep.keys_over_90_days * 6 + hygiene_rep.public_iam_bindings_count * 10)
    p4 -= min(10, hygiene_rep.open_firewall_rules_count * 4 + hygiene_rep.overprivileged_sa_bindings_count * 3)
    p4 = max(0, p4)

    # Pillar 5: MSA Change Governance Readiness (15 pts)
    p5 = 15
    p5 -= min(9, int(msa_radar.get("urgent_or_overdue_count") or 0) * 3)
    p5 -= min(6, int(msa_radar.get("unowned_high_priority_count") or 0) * 2)
    p5 = max(0, p5)

    total_score = p1 + p2 + p3 + p4 + p5
    grade = (
        "A"
        if total_score >= 85
        else ("B" if total_score >= 70 else ("C" if total_score >= 55 else "D"))
    )

    priority_actions: list[str] = []
    if hygiene_rep.open_firewall_rules_count > 0:
        priority_actions.append(
            f"🔥 立即收敛 {hygiene_rep.open_firewall_rules_count} 条对公网 `0.0.0.0/0` 暴露高危端口或全协议的 VPC 防火墙规则"
        )
    if hygiene_rep.keys_over_90_days > 0:
        priority_actions.append(
            f"🔐 轮换或吊销 {hygiene_rep.keys_over_90_days} 把已超过 90 天未轮换的静态服务账号密钥"
        )
    if hygiene_rep.overprivileged_sa_bindings_count > 0:
        priority_actions.append(
            f"🛡️ 收敛 {hygiene_rep.overprivileged_sa_bindings_count} 个持有 Editor/Owner 的默认计算/应用服务账号权限"
        )
    if finops_gov.idle_waste_items:
        priority_actions.append(
            f"🗑️ 回收 {len(finops_gov.idle_waste_items)} 项闲置计费资源（预计立省 ${finops_gov.estimated_monthly_waste_usd:.2f}/月）"
        )
    if finops_gov.unlabeled_spend_pct >= 30.0:
        priority_actions.append(
            f"🏷️ 治理无标签黑盒支出（近7日无标签占比 {finops_gov.unlabeled_spend_pct:.1f}% / ${finops_gov.unlabeled_net_cost_7d_usd:.2f}）"
        )
    if quota_rep.critical_over_90:
        priority_actions.append(
            f"📈 为 {len(quota_rep.critical_over_90)} 项 ≥90% 红线配额提交 QuotaPreference 提额单"
        )
    if int(msa_radar.get("urgent_or_overdue_count") or 0) > 0:
        priority_actions.append(
            f"📌 核查并闭环 {msa_radar.get('urgent_or_overdue_count')} 项已临期/过节点的强制服务变更公告 (MSA)"
        )

    return {
        "score": total_score,
        "grade": grade,
        "pillars": {
            "cost_and_budget_25": p1,
            "waste_and_tagging_20": p2,
            "quota_headroom_20": p3,
            "iam_and_key_security_20": p4,
            "msa_readiness_15": p5,
        },
        "summary_metrics": {
            "as_of_date": daily_bill.target_date,
            "mtd_net_usd": finops_gov.mtd_net_cost_usd,
            "eom_forecast_usd": finops_gov.eom_forecast_net_usd,
            "monthly_budget_usd": finops_gov.monthly_budget_usd,
            "esr_pct": finops_gov.effective_savings_rate_pct,
            "monthly_waste_usd": finops_gov.estimated_monthly_waste_usd,
            "label_compliance_pct": finops_gov.label_compliance_pct,
            "projects_scanned": len(quota_rep.projects_scanned),
            "quota_critical_count": len(quota_rep.critical_over_90),
            "sa_keys_over_90d": hygiene_rep.keys_over_90_days,
            "open_firewall_rules": hygiene_rep.open_firewall_rules_count,
            "overprivileged_default_sas": hygiene_rep.overprivileged_sa_bindings_count,
            "msa_active_count": msa_radar.get("active_actionable_count", 0),
        },
        "priority_actions": priority_actions,
    }


def build_executive_health_feishu_card(data: dict[str, Any]) -> dict[str, Any]:
    """Render an Executive Account Admin Health Scorecard (0-100) Feishu card."""
    score = int(data.get("score") or 0)
    grade = str(data.get("grade") or "B")
    m = data.get("summary_metrics") or {}
    p = data.get("pillars") or {}
    actions = list(data.get("priority_actions") or [])

    template = "green" if score >= 85 else ("orange" if score >= 65 else "red")
    title = f"🏆 GCP 云账户管理员全景治理健康分：{score}/100（评级 {grade}）"

    overview = (
        f"评估基准日: {m.get('as_of_date')} | 纳管活跃项目: {m.get('projects_scanned', 0)} 个\n"
        f"• 成本与预算控制: {p.get('cost_and_budget_25', 0)}/25 "
        f"(MTD ${m.get('mtd_net_usd', 0.0):.2f} -> 月末预测 ${m.get('eom_forecast_usd', 0.0):.2f} / 预算 ${m.get('monthly_budget_usd', 0.0):.0f} | ESR {m.get('esr_pct', 0.0):.1f}%)\n"
        f"• 资源浪费与标签率: {p.get('waste_and_tagging_20', 0)}/20 "
        f"(闲置可省 ${m.get('monthly_waste_usd', 0.0):.2f}/月 | 标签合规率 {m.get('label_compliance_pct', 0.0):.1f}%)\n"
        f"• 配额容量安全垫: {p.get('quota_headroom_20', 0)}/20 (≥90% 红线配额 {m.get('quota_critical_count', 0)} 项)\n"
        f"• 安全与网络基线: {p.get('iam_and_key_security_20', 0)}/20 "
        f"(>90天超期密钥 {m.get('sa_keys_over_90d', 0)} 把 | 高危公网防火墙 {m.get('open_firewall_rules', 0)} 条 | 高危默认SA {m.get('overprivileged_default_sas', 0)} 个)\n"
        f"• MSA 变更治理准备度: {p.get('msa_readiness_15', 0)}/15 (待闭环变更 {m.get('msa_active_count', 0)} 项)"
    )

    elements: list[dict[str, Any]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": overview}},
        {"tag": "hr"},
    ]
    if actions:
        act_text = "【🎯 账户管理员本周优先治理动作 Top 清单】\n" + "\n".join(
            f"{idx}. {a}" for idx, a in enumerate(actions[:6], 1)
        )
    else:
        act_text = "【✅ 治理结论】全组织成本、配额、密钥基线与 MSA 变更均处于最佳状态！"

    elements.append({"tag": "div", "text": {"tag": "plain_text", "content": act_text}})
    elements.append(
        {
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": "提示：可继续追问「查看闲置资源清理命令」「查看超期SA密钥详情」或「自动关联MSA受影响项目」。",
                }
            ],
        }
    )
    return {
        "config": {"wide_screen_mode": True},
        "header": {"template": template, "title": {"tag": "plain_text", "content": title}},
        "elements": elements,
    }


# -----------------------------------------------------------------------------
# ADK FunctionTools across msa/, quota/, and billing/
# -----------------------------------------------------------------------------
def query_msa_radar(status_filter: str = "ALL", query: str = "") -> dict[str, Any]:
    """Query Google Cloud Mandatory Service Announcements (MSA), deadlines, urgency tiers, and impacted projects.

    Args:
        status_filter: 'ALL', 'ACTIVE' (open/in_progress requiring action), 'OPEN', 'IN_PROGRESS', 'MITIGATED', or 'NOT_APPLICABLE'.
        query: Optional product, project ID, or keyword filter (e.g. 'Gemini', 'DNS', 'SQL', 'demo-core-prod').

    Returns:
        Structured MSA governance radar and matching announcement records.
    """
    try:
        svc = get_msa_service()
        if query or status_filter.upper() != "ALL":
            items = [
                r.to_summary_dict() for r in svc.list_msas(status_filter=status_filter, query=query)
            ]
            radar = svc.get_governance_radar()
            return {
                "status": "success",
                "card_type": "MSA",
                "matched_count": len(items),
                "active_actionable_count": radar["active_actionable_count"],
                "urgent_or_overdue_count": radar["urgent_or_overdue_count"],
                "unowned_high_priority_count": radar["unowned_high_priority_count"],
                "items": items,
            }
        radar = svc.get_governance_radar()
        return {"status": "success", "card_type": "MSA", **radar}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def auto_correlate_msa_impacted_projects() -> dict[str, Any]:
    """Automatically correlate MSA announcements to real GCP projects in the Organization based on active Billing Export service usage.

    Returns:
        Summary of profiled active projects and newly correlated MSA blast-radius mappings.
    """
    try:
        corr = get_msa_service().auto_correlate_impacted_projects()
        return {"status": "success", "card_type": "MSA", **corr}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def update_msa_record(
    msa_id_or_keyword: str,
    status: str = "",
    owner: str = "",
    impacted_projects: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Update the governance lifecycle status, owner, impacted GCP projects, or notes of an MSA item.

    Args:
        msa_id_or_keyword: Exact msa_id (e.g. 'msa-xxxxxxxxxx') or unique subject/product keyword.
        status: Optional new status ('OPEN', 'IN_PROGRESS', 'MITIGATED', or 'NOT_APPLICABLE').
        owner: Optional owner name/email.
        impacted_projects: Optional comma-separated GCP project IDs impacted by this MSA.
        notes: Optional progress or verification notes.

    Returns:
        Updated MSA record dictionary.
    """
    try:
        updated = get_msa_service().update_msa_status(
            msa_id_or_keyword=msa_id_or_keyword,
            status=status or None,
            owner=owner if owner != "" else None,
            impacted_projects=impacted_projects if impacted_projects != "" else None,
            notes=notes if notes != "" else None,
        )
        return {"status": "success", "msa": updated.to_summary_dict()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def add_msa_announcement(
    subject: str,
    what_summary: str,
    when_timeline: str,
    next_steps: str = "",
    priority: str = "P2",
    sent_date: str = "",
    impacted_projects: str = "",
) -> dict[str, Any]:
    """Ingest a new Mandatory Service Announcement (MSA) into the governance ledger.

    Args:
        subject: Email subject or announcement title.
        what_summary: Summary of what is changing or retiring.
        when_timeline: Key milestone/retirement dates (e.g. '2027/01/28: Shutdown').
        next_steps: Recommended migration/mitigation actions (if empty, auto-synthesized).
        priority: 'P1', 'P2', 'P3', or 'P4'.
        sent_date: Optional announcement date ('YYYY-MM-DD' or 'YYYY/MM/DD').
        impacted_projects: Optional comma-separated impacted GCP project IDs.

    Returns:
        Newly created or updated MSA record.
    """
    try:
        projs = [p.strip() for p in impacted_projects.split(",") if p.strip()]
        rec = get_msa_service().add_single_msa(
            subject=subject,
            what_summary=what_summary,
            when_timeline=when_timeline,
            next_steps=next_steps,
            priority=priority,
            sent_date=sent_date,
            impacted_projects=projs or None,
        )
        return {"status": "success", "card_type": "MSA", "msa": rec.to_summary_dict()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def scan_project_and_org_quotas(
    project_id: str = "",
    include_org: bool = True,
    critical_threshold_pct: float = 90.0,
) -> dict[str, Any]:
    """Scan Google Cloud Quotas across Projects and Organization concurrently, flagging >=90% critical and 80%-90% warning quotas with gcloud increase commands.

    Args:
        project_id: Optional single GCP project ID to scan, or '' to scan all monitored & discovered Org projects.
        include_org: Whether to also inspect Organization-level Cloud Quotas & Preferences (default True).
        critical_threshold_pct: Alert threshold percentage (default 90.0).

    Returns:
        Structured Project + Org quota utilization report.
    """
    try:
        rep = get_quota_service().scan_all(
            project_filter=project_id,
            include_org=include_org,
            critical_threshold_pct=critical_threshold_pct,
        )
        return {"status": "success", "card_type": "QUOTA", "report": rep.to_dict()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def audit_org_account_security_hygiene() -> dict[str, Any]:
    """Audit Organization-wide Service Account static key age (>90d CIS benchmark), multi-key sprawl, public IAM bindings, and over-privileged default service accounts (`roles/editor` / `roles/owner`).

    Returns:
        Account security & IAM key hygiene findings with copy-paste remediation commands.
    """
    try:
        rep = get_quota_service().audit_hygiene()
        return {"status": "success", "card_type": "HYGIENE", "report": rep.to_dict()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def analyze_billing_export_anomalies(
    target_date: str = "",
    top_n: int = 5,
) -> dict[str, Any]:
    """Analyze daily GCP spend per project from BigQuery Detailed Billing Export, EOM budget forecast, and Top-N suspected anomalies with SKU root causes.

    Args:
        target_date: Optional target date in 'YYYY-MM-DD' format (e.g. '2026-11-08'); pass '' for the latest settled billing day + intraday runaway check.
        top_n: Number of top suspected anomalous projects to return with SKU drilldown (default 5).

    Returns:
        Daily billing summary across all projects plus Top-N anomaly findings and SKU drivers.
    """
    try:
        rep = get_billing_service().generate_daily_report(
            target_date=target_date,
            top_n=top_n,
        )
        return {"status": "success", "card_type": "BILLING", "report": rep.to_dict()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def analyze_finops_governance_and_waste(
    monthly_budget_usd: float = 0.0,
    as_of_date: str = "",
) -> dict[str, Any]:
    """Analyze Month-End (EOM) Run-Rate Budget Forecast, Effective Savings Rate (ESR / CUD / SUD credits), Cost Allocation Label/Tag compliance, Top-10 costly individual resources, and live Idle/Zombie billable resources (unused static IPs, orphan disks, stopped VMs, >90d snapshots).

    Args:
        monthly_budget_usd: Optional monthly budget target in USD (pass 0.0 to use configured default).
        as_of_date: Optional date 'YYYY-MM-DD' (pass '' for latest settled day).

    Returns:
        Comprehensive FinOps governance, resource attribution, and waste reclamation report.
    """
    try:
        rep = get_billing_service().generate_finops_governance_report(
            monthly_budget_usd=monthly_budget_usd if monthly_budget_usd > 0 else None,
            as_of_date=as_of_date,
        )
        return {"status": "success", "card_type": "FINOPS_GOV", "report": rep.to_dict()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def analyze_network_and_architecture_finops(lookback_days: int = 14) -> dict[str, Any]:
    """Audit fixed-hourly architectural costs (Intra-Org Cloud VPN vs free VPC Peering, Cloud/DNS Armor policy sprawl, LB forwarding rules, Cloud Run min-instances) and BigQuery heavy SQL job culprits (`INFORMATION_SCHEMA.JOBS_BY_PROJECT`).

    Args:
        lookback_days: Number of days to analyze (default 14).

    Returns:
        Network category spend, architectural savings recommendations, and heavy BigQuery SQL jobs.
    """
    try:
        rep = get_billing_service().analyze_architecture(lookback_days=lookback_days)
        return {"status": "success", "card_type": "ARCH_FINOPS", "report": rep}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def snooze_governance_finding(
    finding_key: str,
    reason: str = "",
    days: int = 7,
) -> dict[str, Any]:
    """Snooze/acknowledge a known security, firewall, key, or idle-resource finding for N days to prevent alert fatigue.

    Args:
        finding_key: Resource ID, key prefix (e.g. 'a1b2c3d4e5f6'), firewall rule name (e.g. 'testing-allow-ssh'), or 'project:category'.
        reason: Reason for temporary exemption or acknowledgement.
        days: Number of days to mute (1 to 90, default 7).

    Returns:
        Recorded alert snooze entry.
    """
    try:
        entry = get_msa_service().snooze_finding(finding_key=finding_key, reason=reason, days=days)
        invalidate_cache()
        return {"status": "success", "snooze": entry}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def export_msa_governance_ledger(include_audit_log: bool = True) -> dict[str, Any]:
    """Export the healed, project-correlated MSA governance ledger as TSV text and retrieve recent status audit history.

    Args:
        include_audit_log: Whether to include recent MSA status change audit events.

    Returns:
        TSV export preview, total line count, and audit trail records.
    """
    try:
        svc = get_msa_service()
        tsv = svc.export_ledger_tsv()
        events = svc.list_audit_events(limit=15) if include_audit_log else []
        return {
            "status": "success",
            "tsv_content": tsv,
            "audit_events": events,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def get_executive_account_health_score(monthly_budget_usd: float = 0.0) -> dict[str, Any]:
    """Generate a 0-100 Executive Cloud Account & FinOps Health Scorecard across Cost/Budget, Waste/Tagging, Quota Headroom, IAM/SA Key Hygiene, and MSA Readiness.

    Args:
        monthly_budget_usd: Optional monthly budget override in USD (0.0 uses default).

    Returns:
        0-100 health score, letter grade, 5-pillar breakdown, and prioritized admin action items.
    """
    try:
        scorecard = compute_executive_health_report(monthly_budget_usd=monthly_budget_usd)
        return {"status": "success", "card_type": "EXEC_HEALTH", **scorecard}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def run_full_governance_patrol(target_date: str = "") -> dict[str, Any]:
    """Execute a comprehensive Cloud Governance & FinOps patrol covering MSA deadlines, Project/Org Quotas (>=90%), and Daily Billing Anomalies.

    Args:
        target_date: Optional billing date 'YYYY-MM-DD', or '' for latest settled day.

    Returns:
        Combined MSA, Quota, and Billing patrol summary.
    """
    try:
        from bot.scheduler import get_patrol_scheduler

        res = get_patrol_scheduler().run_patrol(
            scope="ALL", target_date=target_date, push_to_feishu=False
        )
        return {
            "status": "success",
            "card_type": "ALL",
            "msa_active_count": res["msa"]["active_actionable_count"],
            "msa_urgent_count": res["msa"]["urgent_or_overdue_count"],
            "quota_critical_count": len(res["quota"]["critical_over_90"]),
            "quota_warning_count": len(res["quota"]["warning_80_to_90"]),
            "billing_target_date": res["billing"]["target_date"],
            "billing_total_net_cost": res["billing"]["total_net_cost"],
            "billing_eom_forecast_usd": res["billing"].get("eom_forecast_net_cost", 0.0),
            "billing_anomalies": res["billing"]["suspected_anomalies"],
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


ALL_GOV_TOOLS = [
    query_msa_radar,
    auto_correlate_msa_impacted_projects,
    update_msa_record,
    add_msa_announcement,
    export_msa_governance_ledger,
    scan_project_and_org_quotas,
    audit_org_account_security_hygiene,
    analyze_billing_export_anomalies,
    analyze_finops_governance_and_waste,
    analyze_network_and_architecture_finops,
    snooze_governance_finding,
    get_executive_account_health_score,
    run_full_governance_patrol,
]

AGENT_INSTRUCTION = """你是企业级 **Google Cloud 账户管理员与云管/FinOps 智能专家 (Cloud Governance & FinOps Agent)**。
你通过专用飞书机器人「GCP 云管与账单雷达」服务云平台管理员（CMP）、安全治理与财务运营（FinOps）团队，统一管理三大核心领域与十三项治理能力：

1. **MSA 强制服务公告、爆炸半径映射与合规审计 (`msa/`)**：
   - 追踪产品退役（如 Gemini 2.5 退役）、破坏性配置变更（如 Cloud DNS CNAME）、计费调整与 API 自动启用通知。
   - 调用 `auto_correlate_msa_impacted_projects` 结合真实账单活跃服务自动识别受影响项目；调用 `query_msa_radar` 查询；调用 `update_msa_record` 流转状态并写入审计日志；调用 `export_msa_governance_ledger` 导出清洁 TSV 台账与审计轨迹。

2. **Project + Org 双层配额（含 429 历史限流回溯）与账户安全/防火墙基线 (`quota/`)**：
   - **配额水位与 429 历史回溯 (`scan_project_and_org_quotas`)**：并发扫描全组织活跃项目与组织级配额，同时查询近 7 天实际触发的 `serviceruntime.googleapis.com/quota/exceeded` 429 限流事件，避免凌晨瞬时限流漏报。
   - **账户 IAM、静态密钥与 VPC 公网防火墙审计 (`audit_org_account_security_hygiene`)**：识别 `>90 天` 超期静态密钥、多密钥泛滥、顶层公共 IAM (`allUsers`)、高危默认 SA (`roles/editor` / `roles/owner`)，以及对 `0.0.0.0/0` 放行全协议 (`all`) 或高危端口 (`22/3389/3306/5432/6379`) 的 VPC 防火墙规则。
   - **告警静默豁免 (`snooze_governance_finding`)**：当管理员确认某项风险已知悉或临时豁免时，可静默指定天数防止告警疲劳。

3. **FinOps 每日异常归因、预算预测、僵尸资源清查与云架构固定成本优化 (`billing/`)**：
   - **每日账单与异常下钻 (`analyze_billing_export_anomalies`)**：区分 T-1 完整结算日与 T-0 盘中冲高，归集 `_BILLING_ACCOUNT_LEVEL_` 公共分摊，定位 Top-N 异常项目与 SKU。
   - **预算预测、ESR、标签合规与僵尸资源 (`analyze_finops_governance_and_waste`)**：计算月末净支出预测 (EOM Run-Rate)、综合节省率 (ESR)、无标签黑盒成本占比、单资源成本 Top 10 及闲置静态 IP/孤儿磁盘/关机 VM。
   - **架构级固定成本与 BigQuery 重查询深潜 (`analyze_network_and_architecture_finops`)**：识别同组织跨项目计费 Cloud VPN（建议改用免费 VPC Peering）、Cloud/DNS Armor 策略冗余、负载均衡转发规则常驻开销及高消耗 BigQuery SQL 任务归因。

4. **账户管理员全景健康分 (`get_executive_account_health_score`)**：
   - 输出 **0–100 分五维治理评分卡**与本周最优先整改清单。

5. **输出规范**：
   - 严禁编造任何金额、配额、密钥 ID、防火墙名称或资源名，100% 忠实于工具返回的真实数据。
   - 使用结构化中文 Markdown 输出关键结论、风险等级与可直接复制执行的 `gcloud` 修复参考命令；系统会自动附上对应的飞书交互卡片。
"""

root_agent = Agent(
    name="cloud_gov_finops_agent",
    model=Gemini(
        model=MODEL,
        retry_options=types.HttpRetryOptions(attempts=2),
    ),
    instruction=AGENT_INSTRUCTION,
    tools=ALL_GOV_TOOLS,
)

adk_app = App(root_agent=root_agent, name="cloud_gov_finops")


def build_cards_for_tool_types(
    card_types: list[str], target_date: str = "", interactive_callbacks: bool = False
) -> list[dict[str, Any]]:
    """Build Feishu interactive visual cards matching the tools invoked during an agent turn."""
    cards: list[dict[str, Any]] = []
    expanded: list[str] = []
    for ct in card_types:
        if ct == "ALL":
            expanded.extend(["MSA", "QUOTA", "BILLING"])
        elif ct in (
            "MSA",
            "QUOTA",
            "BILLING",
            "FINOPS_GOV",
            "HYGIENE",
            "EXEC_HEALTH",
            "ARCH_FINOPS",
        ):
            expanded.append(ct)

    for ct in dict.fromkeys(expanded):
        try:
            if ct == "MSA":
                cards.append(
                    build_msa_feishu_card(
                        get_msa_service().get_governance_radar(),
                        interactive_callbacks=interactive_callbacks,
                    )
                )
            elif ct == "QUOTA":
                cards.append(
                    build_quota_feishu_card(get_quota_service().scan_all_cached(include_org=True))
                )
            elif ct == "BILLING":
                cards.append(
                    build_billing_feishu_card(
                        get_billing_service().generate_daily_report_cached(target_date=target_date)
                    )
                )
            elif ct == "FINOPS_GOV":
                cards.append(
                    build_finops_governance_feishu_card(
                        get_billing_service().generate_finops_governance_report(
                            as_of_date=target_date
                        )
                    )
                )
            elif ct == "HYGIENE":
                cards.append(
                    build_account_hygiene_feishu_card(get_quota_service().audit_hygiene())
                )
            elif ct == "EXEC_HEALTH":
                cards.append(
                    build_executive_health_feishu_card(compute_executive_health_report())
                )
            elif ct == "ARCH_FINOPS":
                cards.append(
                    build_architecture_finops_feishu_card(
                        get_billing_service().analyze_architecture()
                    )
                )
        except Exception as exc:
            logger.warning("Failed building %s card: %s", ct, type(exc).__name__)
    return cards


def run_deterministic_gov_turn(message: str) -> dict[str, Any]:
    """Deterministic fallback orchestrator used when `CHAT_ENGINE=deterministic`."""
    text = (message or "").strip()
    lower = text.lower()
    date_match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", text)
    target_date = date_match.group(1) if date_match else ""

    if any(k in lower for k in ("体检", "健康分", "评分", "executive", "health")):
        sc = get_executive_account_health_score()
        return {
            "reply": (
                f"🏆 **云账户治理健康评分：{sc.get('score')}/100（评级 `{sc.get('grade')}`）**\n"
                + "\n".join(f"- {a}" for a in (sc.get("priority_actions") or [])[:5])
            ),
            "cards": build_cards_for_tool_types(["EXEC_HEALTH"]),
        }

    if any(k in lower for k in ("闲置", "僵尸", "浪费", "标签", "预测", "节省率", "esr", "waste")):
        gov = analyze_finops_governance_and_waste(as_of_date=target_date)["report"]
        return {
            "reply": (
                f"💡 **FinOps 预算预测与浪费清查 (`{gov['as_of_date']}`)**：\n"
                f"- 月末预测: **${gov['eom_forecast_net_usd']:.2f}** / 预算 **${gov['monthly_budget_usd']:.0f}** (`{gov['budget_status']}`)\n"
                f"- 综合节省率 (ESR): **{gov['effective_savings_rate_pct']:.1f}%** | 标签合规率: **{gov['label_compliance_pct']:.1f}%**\n"
                f"- 闲置可回收浪费: **${gov['estimated_monthly_waste_usd']:.2f}/月**（共 **{len(gov['idle_waste_items'])}** 项）"
            ),
            "cards": build_cards_for_tool_types(["FINOPS_GOV"], target_date=target_date),
        }

    if any(k in lower for k in ("网络", "vpn", "peering", "armor", "架构优化", "sql任务", "arch")):
        arch = analyze_network_and_architecture_finops()["report"]
        return {
            "reply": (
                f"🏗️ **云架构固定成本优化分析**：预计月度可优化空间 **${arch['estimated_monthly_arch_savings_usd']:.2f}/月**，"
                f"共识别 **{len(arch['architectural_recommendations'])}** 项架构降本机会。"
            ),
            "cards": build_cards_for_tool_types(["ARCH_FINOPS"]),
        }

    if any(k in lower for k in ("密钥", "key", "iam", "安全基线", "权限审计", "防火墙", "firewall", "hygiene")):
        hyg = audit_org_account_security_hygiene()["report"]
        return {
            "reply": (
                f"🔐 **云账户 IAM、密钥与防火墙安全审计**：\n"
                f"- >90天超期密钥: **{hyg['keys_over_90_days']}** 把 | 高危公网防火墙 (0.0.0.0/0): **{hyg['open_firewall_rules_count']}** 条\n"
                f"- 公共 IAM 暴露: **{hyg['public_iam_bindings_count']}** 项 | 默认 SA 持有 Editor/Owner: **{hyg['overprivileged_sa_bindings_count']}** 项"
            ),
            "cards": build_cards_for_tool_types(["HYGIENE"]),
        }

    if any(k in lower for k in ("全面巡检", "全量巡检", "早报", "汇总所有", "patrol")):
        res = run_full_governance_patrol(target_date=target_date)
        cards = build_cards_for_tool_types(["ALL"], target_date=target_date)
        return {
            "reply": (
                f"📋 **云管与 FinOps 全景巡检完成**\n"
                f"- **MSA 待闭环公告**: **{res.get('msa_active_count', 0)}** 项（临期/待核查 **{res.get('msa_urgent_count', 0)}** 项）\n"
                f"- **Quota 配额告警**: ≥90% 危急 **{res.get('quota_critical_count', 0)}** 项 | 80%-90% 预警 **{res.get('quota_warning_count', 0)}** 项\n"
                f"- **每日账单 ({res.get('billing_target_date')})**: 总净支出 **${res.get('billing_total_net_cost', 0.0):.2f}**（月末预测 **${res.get('billing_eom_forecast_usd', 0.0):.2f}**），识别疑似异常项目 **{len(res.get('billing_anomalies') or [])}** 个"
            ),
            "cards": cards,
        }

    if "msa" in lower or "公告" in lower or "退役" in lower:
        if any(k in lower for k in ("关联", "匹配", "correlate")):
            corr = auto_correlate_msa_impacted_projects()
            return {
                "reply": f"✅ 已根据活跃账单自动关联受影响项目，共更新 **{corr.get('msas_updated', 0)}** 条 MSA。",
                "cards": build_cards_for_tool_types(["MSA"]),
            }
        if any(k in lower for k in ("标记", "更新", "mitigated", "已处理", "已完成", "in_progress")):
            id_m = re.search(r"\b(msa-[a-f0-9]{6,12})\b", lower)
            key = id_m.group(1) if id_m else "Gemini"
            st = (
                "MITIGATED"
                if any(k in lower for k in ("mitigated", "已处理", "已完成"))
                else "IN_PROGRESS"
            )
            upd = update_msa_record(key, status=st)
            if upd["status"] == "success":
                m = upd["msa"]
                return {
                    "reply": f"✅ 已将 MSA `{m['msa_id']}`（{m['product_service']}）状态更新为 **`{m['status']}`**。",
                    "cards": [],
                }
        res = query_msa_radar()
        return {
            "reply": (
                f"📌 **MSA 服务公告治理汇总**：共纳管 **{res.get('total_records', 0)}** 条公告，"
                f"当前待闭环 **{res.get('active_actionable_count', 0)}** 条（其中临期/已过节点待确认 **{res.get('urgent_or_overdue_count', 0)}** 条）。"
            ),
            "cards": build_cards_for_tool_types(["MSA"]),
        }

    if any(k in lower for k in ("quota", "配额", "额度", "90%")):
        res = scan_project_and_org_quotas()
        rep = res["report"]
        return {
            "reply": (
                f"📊 **GCP Project & Org 配额扫描完成**（组织 `{rep['org_id']}`，项目 `{', '.join(rep['projects_scanned'])}`）：\n"
                f"- 🔴 **≥90% 危急配额**: **{len(rep['critical_over_90'])}** 项\n"
                f"- 🟠 **80%–90% 预警配额**: **{len(rep['warning_80_to_90'])}** 项"
            ),
            "cards": build_cards_for_tool_types(["QUOTA"]),
        }

    res = analyze_billing_export_anomalies(target_date=target_date)
    rep = res["report"]
    anoms = rep["suspected_anomalies"]
    return {
        "reply": (
            f"💰 **GCP 每日账单与异常检测报告 (`{rep['target_date']}`)**：\n"
            f"- 当日总净支出: **${rep['total_net_cost']:.2f}**（Gross `${rep['total_gross_cost']:.2f}`，DoD `${rep['total_dod_delta_net']:+.2f}`）\n"
            f"- 当月累计 (MTD): **${rep['mtd_total_net_cost']:.2f}**（月末预测 **${rep['eom_forecast_net_cost']:.2f}**）\n"
            f"- 疑似异常/差异显著项目: **{len(anoms)}** 个"
        ),
        "cards": build_cards_for_tool_types(["BILLING"], target_date=target_date),
    }
