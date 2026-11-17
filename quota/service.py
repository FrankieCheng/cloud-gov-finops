# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Quota Governance Service (Project + Org rollup, >=90% alerting, and Feishu Card builder)."""

from __future__ import annotations

import concurrent.futures
import datetime
import os
import urllib.error
from collections import defaultdict
from typing import Any

from bot import config
from bot.cache import cached_call
from quota.hygiene import audit_account_hygiene
from quota.models import (
    AccountHygieneReport,
    QuotaExceededEvent,
    QuotaMetricItem,
    QuotaRiskLevel,
    QuotaScanReport,
)
from quota.scanner import (
    discover_org_projects_live,
    get_mock_quota_fixture,
    scan_compute_quotas_live,
    scan_organization_quotas_live,
    scan_quota_exceeded_events_live,
    scan_serviceruntime_quotas_live,
)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class QuotaGovernanceService:
    """Evaluates Project-level and Organization-level quotas and identifies >=90% exhaustion risks."""

    def __init__(
        self,
        org_id: str | None = None,
        projects: list[str] | None = None,
        critical_threshold_pct: float | None = None,
        warning_threshold_pct: float | None = None,
    ) -> None:
        self.org_id = org_id if org_id is not None else config.get_org_id()
        self.projects = projects if projects is not None else config.get_monitored_projects()
        self.critical_pct = (
            critical_threshold_pct
            if critical_threshold_pct is not None
            else float(os.getenv("QUOTA_CRITICAL_THRESHOLD_PCT", "90.0"))
        )
        self.warning_pct = (
            warning_threshold_pct
            if warning_threshold_pct is not None
            else float(os.getenv("QUOTA_WARNING_THRESHOLD_PCT", "80.0"))
        )

    def scan_all(
        self,
        project_filter: str = "",
        include_org: bool = True,
        critical_threshold_pct: float | None = None,
    ) -> QuotaScanReport:
        crit = critical_threshold_pct if critical_threshold_pct is not None else self.critical_pct
        warn = min(self.warning_pct, crit)
        mode = config.get_api_mode()

        target_projects = (
            [config.validate_project_id(project_filter)]
            if project_filter and project_filter.strip()
            else list(self.projects)
        )

        all_metrics: list[QuotaMetricItem] = []
        exceeded_events: list[QuotaExceededEvent] = []
        scanned_projects: list[str] = []
        diagnostics: list[dict[str, str]] = []

        if mode == "MOCK":
            proj_items, org_items, org_prefs = get_mock_quota_fixture(
                self.org_id, target_projects, crit, warn
            )
            scanned_projects = list(target_projects)
            all_metrics.extend(proj_items)
            exceeded_events.append(
                QuotaExceededEvent(
                    project_id=target_projects[0] if target_projects else "demo-core-prod",
                    service="aiplatform.googleapis.com",
                    quota_metric="aiplatform.googleapis.com/online_prediction_requests_per_base_model",
                    location="global",
                    exceeded_count_7d=14,
                    latest_exceeded_at="2026-11-15T18:20:00Z",
                )
            )
            if include_org:
                all_metrics.extend(org_items)
            else:
                org_items = []
                org_prefs = []
        else:
            token = config.get_gcp_access_token()
            if include_org and not project_filter:
                discovered = discover_org_projects_live(self.org_id, token)
                for dp in discovered:
                    if dp not in target_projects:
                        target_projects.append(dp)

            def _scan_one_proj(
                pid: str,
            ) -> tuple[str, list[QuotaMetricItem], list[QuotaExceededEvent], dict[str, str] | None]:
                try:
                    c_items = scan_compute_quotas_live(pid, token, crit, warn)
                    s_items = scan_serviceruntime_quotas_live(pid, token, crit, warn)
                    ex_items = scan_quota_exceeded_events_live(pid, token, days=7)
                    return pid, c_items + s_items, ex_items, None
                except urllib.error.HTTPError as exc:
                    return (
                        pid,
                        [],
                        [],
                        {
                            "scope": f"projects/{pid}",
                            "status": f"HTTP_{exc.code}",
                            "message": f"项目 `{pid}` 缺少配额读取权限（HTTP {exc.code}），已跳过。",
                        },
                    )
                except Exception as exc:
                    return (
                        pid,
                        [],
                        [],
                        {
                            "scope": f"projects/{pid}",
                            "status": type(exc).__name__,
                            "message": f"项目 `{pid}` 配额采集异常: {type(exc).__name__}",
                        },
                    )

            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                for pid, p_metrics, p_ex, diag in pool.map(_scan_one_proj, target_projects):
                    if diag is not None:
                        diagnostics.append(diag)
                    else:
                        all_metrics.extend(p_metrics)
                        exceeded_events.extend(p_ex)
                        scanned_projects.append(pid)

            org_items = []
            org_prefs = []
            if include_org and self.org_id:
                org_items, org_prefs, org_diags = scan_organization_quotas_live(
                    self.org_id, token, crit, warn
                )
                diagnostics.extend(org_diags)
                all_metrics.extend(org_items)

        all_metrics.sort(key=lambda m: (m.utilization_pct, m.usage), reverse=True)
        critical_list = [m for m in all_metrics if m.risk_level == QuotaRiskLevel.CRITICAL]
        warning_list = [m for m in all_metrics if m.risk_level == QuotaRiskLevel.WARNING]
        top_utilized = [m for m in all_metrics if m.utilization_pct > 0][:15]

        # Build Org-wide cross-project hot metrics rollup
        by_metric: dict[str, list[QuotaMetricItem]] = defaultdict(list)
        for m in all_metrics:
            if m.utilization_pct > 0:
                by_metric[m.metric].append(m)

        org_hot_summary: list[dict[str, Any]] = []
        for metric_name, group in by_metric.items():
            peak_item = max(group, key=lambda x: x.utilization_pct)
            org_hot_summary.append(
                {
                    "metric": metric_name,
                    "service": peak_item.service,
                    "projects_affected": len({g.scope_id for g in group}),
                    "max_utilization_pct": peak_item.utilization_pct,
                    "peak_scope": f"{peak_item.scope_type}:{peak_item.scope_id} ({peak_item.region})",
                    "projects_over_90": [
                        g.scope_id for g in group if g.utilization_pct >= crit
                    ],
                }
            )
        org_hot_summary.sort(key=lambda x: float(x["max_utilization_pct"]), reverse=True)

        return QuotaScanReport(
            generated_at=_utc_now_iso(),
            mode=mode,
            org_id=self.org_id,
            projects_requested=target_projects,
            projects_scanned=scanned_projects,
            critical_threshold_pct=crit,
            warning_threshold_pct=warn,
            total_metrics_evaluated=len(all_metrics),
            critical_over_90=critical_list,
            warning_80_to_90=warning_list,
            top_utilized=top_utilized,
            recent_exceeded_events=exceeded_events,
            org_quota_items=org_items,
            org_quota_preferences=org_prefs,
            org_hot_metrics_summary=org_hot_summary[:10],
            access_diagnostics=diagnostics,
        )

    def scan_all_cached(
        self,
        project_filter: str = "",
        include_org: bool = True,
        critical_threshold_pct: float | None = None,
        force_refresh: bool = False,
    ) -> QuotaScanReport:
        cache_key = f"quota:{project_filter}:{include_org}:{critical_threshold_pct}"
        return cached_call(
            cache_key,
            lambda: self.scan_all(project_filter, include_org, critical_threshold_pct),
            force_refresh=force_refresh,
        )

    def audit_hygiene(
        self, projects: list[str] | None = None, force_refresh: bool = False
    ) -> AccountHygieneReport:
        """Audit Org-wide Service Account static key age/sprawl, VPC firewalls, and high-risk IAM bindings."""
        cache_key = f"hygiene:{','.join(projects or [])}"
        return cached_call(
            cache_key,
            lambda: audit_account_hygiene(org_id=self.org_id, projects=projects or self.projects),
            force_refresh=force_refresh,
        )


def build_quota_feishu_card(report: QuotaScanReport | dict[str, Any]) -> dict[str, Any]:
    """Render a Feishu interactive Quota Governance card covering Project + Org scopes."""
    data = report.to_dict() if isinstance(report, QuotaScanReport) else report
    crit_items = list(data.get("critical_over_90") or [])
    warn_items = list(data.get("warning_80_to_90") or [])
    top_items = list(data.get("top_utilized") or [])
    exceeded = list(data.get("recent_exceeded_events") or [])
    diags = list(data.get("access_diagnostics") or [])
    crit_th = data.get("critical_threshold_pct", 90.0)

    if crit_items or exceeded:
        template = "red"
        title = (
            f"🚨 GCP 配额超限/429限流告警（≥{crit_th:.0f}%: {len(crit_items)} 项 | 近7日触发429: {len(exceeded)} 项）"
        )
    elif warn_items:
        template = "orange"
        title = f"⚠️ GCP 配额高水位提醒（{len(warn_items)} 项 ≥80%）"
    else:
        template = "green"
        title = "✅ GCP 项目与组织配额巡检正常（无 ≥90% 及近7日无 429 限流）"

    header_summary = (
        f"组织 ID: {data.get('org_id') or '未配置'} | "
        f"已扫描项目 ({len(data.get('projects_scanned') or [])}): {', '.join(data.get('projects_scanned') or []) or '无'}\n"
        f"评估活跃配额项: {data.get('total_metrics_evaluated', 0)} | "
        f"🔴 ≥{crit_th:.0f}% 危急: {len(crit_items)} | 🟠 80%-{crit_th:.0f}% 预警: {len(warn_items)} | "
        f"⚡ 近7日 429 超限事件: {len(exceeded)}"
    )
    elements: list[dict[str, Any]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": header_summary}},
        {"tag": "hr"},
    ]

    body_sections: list[str] = []
    if exceeded:
        ex_lines = ["【⚡ 近 7 日实际触发 429 Quota Exceeded 限流历史回溯】"]
        for ev in exceeded[:6]:
            ex_lines.append(
                f"• [{ev.get('project_id')} | {ev.get('location')}] {ev.get('quota_metric')}: "
                f"触发 {ev.get('exceeded_count_7d')} 次超限拒绝（最近: {ev.get('latest_exceeded_at')[:19]}Z）"
            )
        body_sections.append("\n".join(ex_lines))

    if crit_items:
        lines = [f"【🔴 已达或超过 {crit_th:.0f}% 紧急配额清单】"]
        for item in crit_items[:10]:
            scope_tag = "组织级" if item.get("scope_type") == "ORGANIZATION" else f"项目 {item.get('scope_id')}"
            lines.append(
                f"• [{scope_tag} | {item.get('region')}] {item.get('display_name')}: "
                f"{item.get('usage'):g} / {item.get('limit'):g} ({item.get('utilization_pct'):.1f}%)\n"
                f"  ↳ {item.get('recommendation')}"
            )
        body_sections.append("\n".join(lines))

    if warn_items:
        lines = ["【🟠 80%–90% 临近预警配额】"]
        for item in warn_items[:6]:
            scope_tag = "组织级" if item.get("scope_type") == "ORGANIZATION" else f"项目 {item.get('scope_id')}"
            lines.append(
                f"• [{scope_tag} | {item.get('region')}] {item.get('display_name')}: "
                f"{item.get('usage'):g} / {item.get('limit'):g} ({item.get('utilization_pct'):.1f}%)"
            )
        body_sections.append("\n".join(lines))

    if not crit_items and not warn_items:
        lines = ["【📊 当前最高水位配额 Top 6（全部安全 <80%）】"]
        if top_items:
            for item in top_items[:6]:
                lines.append(
                    f"• [{item.get('scope_id')} | {item.get('region')}] {item.get('display_name')}: "
                    f"{item.get('usage'):g} / {item.get('limit'):g} ({item.get('utilization_pct'):.1f}%)"
                )
        else:
            lines.append("• 所有受检配额当前使用率均为 0% 或远低于安全阈值。")
        body_sections.append("\n".join(lines))

    org_prefs = list(data.get("org_quota_preferences") or [])
    reconciling_prefs = [p for p in org_prefs if p.get("reconciling")]
    if reconciling_prefs:
        p_lines = ["【⏳ 组织级审批中的配额调整单 (Org QuotaPreferences)】"]
        for p in reconciling_prefs[:5]:
            p_lines.append(
                f"• {p.get('service')} / {p.get('quota_id')}: 申请目标值 {p.get('preferred_value'):g}（审批中）"
            )
        body_sections.append("\n".join(p_lines))

    if diags:
        d_lines = ["【ℹ️ 跨项目 / 组织级权限覆盖提示】"]
        for d in diags[:4]:
            d_lines.append(f"• [{d.get('scope')}]: {str(d.get('message') or '')[:220]}")
        body_sections.append("\n".join(d_lines))

    elements.append(
        {"tag": "div", "text": {"tag": "plain_text", "content": "\n\n".join(body_sections)[:3800]}}
    )
    elements.append(
        {
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": "云管建议：对 ≥90% 的配额可通过 Cloud Quotas API 提交 QuotaPreference 提额，若遇大促/扩容锁定请提前联动工单助手发起配额协调。",
                }
            ],
        }
    )
    return {
        "config": {"wide_screen_mode": True},
        "header": {
            "template": template,
            "title": {"tag": "plain_text", "content": title},
        },
        "elements": elements,
    }


_quota_service_instance: QuotaGovernanceService | None = None


def get_quota_service() -> QuotaGovernanceService:
    global _quota_service_instance
    if _quota_service_instance is None:
        _quota_service_instance = QuotaGovernanceService()
    return _quota_service_instance


def set_quota_service(svc: QuotaGovernanceService | None) -> None:
    global _quota_service_instance
    _quota_service_instance = svc
