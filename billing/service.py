# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""FinOps Billing Service and Feishu Interactive Daily Spend & Anomaly Card Builder."""

from __future__ import annotations

import datetime
import os
from typing import Any

from billing.analyzer import (
    analyze_daily_series,
    fetch_daily_project_series_live,
    fetch_sku_drivers_live,
    get_mock_billing_series,
    resolve_settled_and_intraday_dates,
)
from billing.architecture_advisor import analyze_architecture_and_bq_finops
from billing.finops_governance import (
    compute_eom_forecast_and_budget,
    fetch_esr_labels_and_resources_live,
    get_mock_finops_governance,
    scan_idle_waste_live,
)
from billing.models import DailyBillingReport, FinOpsGovernanceReport
from bot import config
from bot.cache import cached_call


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class BillingFinOpsService:
    """Summarizes daily GCP spend across all projects and detects Top-N suspected cost anomalies."""

    def __init__(
        self,
        billing_tables: list[str] | None = None,
        timezone: str | None = None,
        top_n: int | None = None,
        min_delta_usd: float | None = None,
        min_pct: float | None = None,
    ) -> None:
        self.billing_tables = (
            billing_tables if billing_tables is not None else config.get_billing_export_tables()
        )
        self.timezone = timezone or config.get_billing_timezone()
        self.top_n = top_n if top_n is not None else int(os.getenv("BILLING_TOP_N_ANOMALIES", "5"))
        self.min_delta_usd = (
            min_delta_usd
            if min_delta_usd is not None
            else float(os.getenv("BILLING_MIN_ANOMALY_DELTA_USD", "1.0"))
        )
        self.min_pct = (
            min_pct
            if min_pct is not None
            else float(os.getenv("BILLING_MIN_ANOMALY_PCT", "20.0"))
        )
        self.monthly_budget_usd = float(os.getenv("BILLING_MONTHLY_BUDGET_USD", "1200.0"))

    def generate_daily_report(
        self,
        target_date: str = "",
        top_n: int | None = None,
        min_delta_usd: float | None = None,
        min_pct: float | None = None,
    ) -> DailyBillingReport:
        mode = config.get_api_mode()
        settled_default, intraday_today = resolve_settled_and_intraday_dates(self.timezone)
        chosen_target = (
            config.validate_iso_date(target_date)
            if target_date and target_date.strip()
            else settled_default
        )
        query_end = max(chosen_target, intraday_today) if not target_date else chosen_target
        intraday_for_check = intraday_today if not target_date else ""

        eff_top_n = top_n if top_n is not None else self.top_n
        eff_min_delta = min_delta_usd if min_delta_usd is not None else self.min_delta_usd
        eff_min_pct = min_pct if min_pct is not None else self.min_pct

        if mode == "MOCK":
            rows, mock_drivers = get_mock_billing_series(query_end)
            summaries, anomalies, intra_alerts, totals = analyze_daily_series(
                rows,
                target_date_iso=chosen_target,
                intraday_date_iso=intraday_for_check,
                top_n=eff_top_n,
                min_delta_usd=eff_min_delta,
                min_pct=eff_min_pct,
            )
            for anom in anomalies:
                anom.top_sku_drivers = mock_drivers.get(anom.project_id, [])
        else:
            rows = fetch_daily_project_series_live(
                self.billing_tables,
                end_date_iso=query_end,
                tz_name=self.timezone,
            )
            summaries, anomalies, intra_alerts, totals = analyze_daily_series(
                rows,
                target_date_iso=chosen_target,
                intraday_date_iso=intraday_for_check,
                top_n=eff_top_n,
                min_delta_usd=eff_min_delta,
                min_pct=eff_min_pct,
            )
            drilldown_pids = list(
                dict.fromkeys(
                    [a.project_id for a in anomalies] + [a.project_id for a in intra_alerts]
                )
            )
            if drilldown_pids:
                drivers_map = fetch_sku_drivers_live(
                    self.billing_tables,
                    target_date_iso=chosen_target,
                    project_ids=drilldown_pids,
                    tz_name=self.timezone,
                )
                for anom in anomalies:
                    anom.top_sku_drivers = drivers_map.get(anom.project_id, [])

        avg_7d_total = sum(p.avg_7d_net_cost for p in summaries)
        fc = compute_eom_forecast_and_budget(
            as_of_date_iso=chosen_target,
            mtd_net_cost=totals["mtd_total_net_cost"],
            avg_7d_daily_net=avg_7d_total,
            monthly_budget_usd=self.monthly_budget_usd,
        )

        currency = summaries[0].currency if summaries else "USD"
        return DailyBillingReport(
            generated_at=_utc_now_iso(),
            mode=mode,
            billing_tables=self.billing_tables,
            timezone=self.timezone,
            target_date=chosen_target,
            currency=currency,
            total_gross_cost=totals["total_gross_cost"],
            total_credits=totals["total_credits"],
            total_net_cost=totals["total_net_cost"],
            prior_day_total_net_cost=totals["prior_day_total_net_cost"],
            total_dod_delta_net=totals["total_dod_delta_net"],
            total_dod_pct_net=totals["total_dod_pct_net"],
            mtd_total_net_cost=totals["mtd_total_net_cost"],
            monthly_budget_usd=self.monthly_budget_usd,
            eom_forecast_net_cost=fc["eom_forecast_net_usd"],
            forecast_budget_pct=fc["forecast_budget_pct"],
            intraday_date=intraday_for_check,
            intraday_total_net_cost=totals["intraday_total_net_cost"],
            projects_summary=summaries,
            suspected_anomalies=anomalies,
            intraday_alerts=intra_alerts,
        )

    def generate_daily_report_cached(
        self, target_date: str = "", top_n: int | None = None, force_refresh: bool = False
    ) -> DailyBillingReport:
        return cached_call(
            f"billing_daily:{target_date}:{top_n}",
            lambda: self.generate_daily_report(target_date=target_date, top_n=top_n),
            force_refresh=force_refresh,
        )

    def generate_finops_governance_report(
        self,
        monthly_budget_usd: float | None = None,
        as_of_date: str = "",
        force_refresh: bool = False,
    ) -> FinOpsGovernanceReport:
        """Build deep FinOps Governance report: EOM Forecast, ESR, Label Audit, Top Resources & Idle Waste."""

        def _compute() -> FinOpsGovernanceReport:
            mode = config.get_api_mode()
            settled_default, _ = resolve_settled_and_intraday_dates(self.timezone)
            chosen_date = (
                config.validate_iso_date(as_of_date)
                if as_of_date and as_of_date.strip()
                else settled_default
            )
            budget = (
                float(monthly_budget_usd)
                if monthly_budget_usd and monthly_budget_usd > 0
                else self.monthly_budget_usd
            )
            if mode == "MOCK":
                rep = get_mock_finops_governance(chosen_date, monthly_budget_usd=budget)
            else:
                daily = self.generate_daily_report_cached(target_date=chosen_date)
                avg_7d_daily = round(sum(p.avg_7d_net_cost for p in daily.projects_summary), 2)
                bq_gov = fetch_esr_labels_and_resources_live(
                    self.billing_tables,
                    as_of_date_iso=chosen_date,
                    tz_name=self.timezone,
                    top_resources_limit=10,
                )
                mtd_net = bq_gov["mtd_net_cost_usd"] or daily.mtd_total_net_cost
                fc = compute_eom_forecast_and_budget(
                    as_of_date_iso=chosen_date,
                    mtd_net_cost=mtd_net,
                    avg_7d_daily_net=avg_7d_daily,
                    monthly_budget_usd=budget,
                )
                waste_items = scan_idle_waste_live(
                    org_id=config.get_org_id(),
                    seed_projects=config.get_monitored_projects(),
                )
                rep = FinOpsGovernanceReport(
                    generated_at=_utc_now_iso(),
                    mode=mode,
                    as_of_date=chosen_date,
                    currency=daily.currency,
                    monthly_budget_usd=budget,
                    mtd_net_cost_usd=mtd_net,
                    avg_7d_daily_net_usd=avg_7d_daily,
                    days_elapsed=fc["days_elapsed"],
                    days_in_month=fc["days_in_month"],
                    eom_forecast_net_usd=fc["eom_forecast_net_usd"],
                    budget_utilization_pct=fc["budget_utilization_pct"],
                    forecast_budget_pct=fc["forecast_budget_pct"],
                    budget_status=fc["budget_status"],
                    mtd_list_cost_usd=bq_gov["mtd_list_cost_usd"],
                    mtd_gross_cost_usd=bq_gov["mtd_gross_cost_usd"],
                    mtd_total_savings_usd=bq_gov["mtd_total_savings_usd"],
                    effective_savings_rate_pct=bq_gov["effective_savings_rate_pct"],
                    credit_breakdown=bq_gov["credit_breakdown"],
                    net_cost_7d_usd=bq_gov["net_cost_7d_usd"],
                    unlabeled_net_cost_7d_usd=bq_gov["unlabeled_net_cost_7d_usd"],
                    unlabeled_spend_pct=bq_gov["unlabeled_spend_pct"],
                    label_compliance_pct=bq_gov["label_compliance_pct"],
                    project_label_gaps=bq_gov["project_label_gaps"],
                    top_resources_7d=bq_gov["top_resources_7d"],
                    idle_waste_items=waste_items,
                    estimated_monthly_waste_usd=round(
                        sum(w.estimated_monthly_waste_usd for w in waste_items), 2
                    ),
                )

            try:
                from msa.service import get_msa_service

                snoozer = get_msa_service()
                filtered_waste = [
                    w
                    for w in rep.idle_waste_items
                    if not snoozer.is_finding_snoozed(
                        w.resource_name, f"{w.project_id}:{w.category}"
                    )
                ]
                rep.idle_waste_items = filtered_waste
                rep.estimated_monthly_waste_usd = round(
                    sum(w.estimated_monthly_waste_usd for w in filtered_waste), 2
                )
            except Exception:
                pass
            return rep

        return cached_call(
            f"finops_gov:{monthly_budget_usd}:{as_of_date}",
            _compute,
            force_refresh=force_refresh,
        )

    def analyze_architecture(
        self, lookback_days: int = 14, force_refresh: bool = False
    ) -> dict[str, Any]:
        return cached_call(
            f"arch_finops:{lookback_days}",
            lambda: analyze_architecture_and_bq_finops(
                tables=self.billing_tables, lookback_days=lookback_days
            ),
            force_refresh=force_refresh,
        )


def build_billing_feishu_card(report: DailyBillingReport | dict[str, Any]) -> dict[str, Any]:
    """Render a Feishu FinOps Daily Billing & Top-N Anomaly Attribution card."""
    data = report.to_dict() if isinstance(report, DailyBillingReport) else report
    anomalies = list(data.get("suspected_anomalies") or [])
    intra_alerts = list(data.get("intraday_alerts") or [])
    projects = list(data.get("projects_summary") or [])

    has_crit = bool(intra_alerts) or any(a.get("severity") == "CRITICAL" for a in anomalies)
    if has_crit:
        template = "red"
        title = f"🚨 GCP 每日账单与异常波动告警 ({data.get('target_date')})"
    elif anomalies:
        template = "orange"
        title = f"⚠️ GCP 每日账单巡检 · 发现 {len(anomalies)} 个疑似异常项目 ({data.get('target_date')})"
    else:
        template = "blue"
        title = f"📊 GCP 每日账单汇总日报 ({data.get('target_date')} · 平稳无异常)"

    dod_pct = data.get("total_dod_pct_net")
    dod_pct_str = f" ({dod_pct:+.1f}%)" if isinstance(dod_pct, int | float) else ""
    overview = (
        f"结算日期: {data.get('target_date')} ({data.get('timezone')}) | 币种: {data.get('currency', 'USD')}\n"
        f"当日总净支出 (Net): ${data.get('total_net_cost', 0.0):.2f} "
        f"(Gross: ${data.get('total_gross_cost', 0.0):.2f}, 折扣/Credits: ${data.get('total_credits', 0.0):.2f})\n"
        f"日环比变动 (DoD): ${data.get('total_dod_delta_net', 0.0):+.2f}{dod_pct_str} | "
        f"当月累计净支出 (MTD): ${data.get('mtd_total_net_cost', 0.0):.2f}"
    )
    if data.get("eom_forecast_net_cost"):
        overview += (
            f"\n月末净支出预测 (EOM Run-Rate): ${data.get('eom_forecast_net_cost', 0.0):.2f} "
            f"/ 月度预算 ${data.get('monthly_budget_usd', 0.0):.0f} ({data.get('forecast_budget_pct', 0.0):.1f}%)"
        )
    if data.get("intraday_date"):
        overview += (
            f"\n今日盘中实时累计 ({data.get('intraday_date')} 未完结): "
            f"${data.get('intraday_total_net_cost', 0.0):.2f}"
        )

    elements: list[dict[str, Any]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": overview}},
        {"tag": "hr"},
    ]

    sections: list[str] = []
    if intra_alerts:
        i_lines = [f"【⚡ 今日盘中实时冲高预警 ({data.get('intraday_date')})】"]
        for al in intra_alerts[:3]:
            i_lines.append(f"• [{al.get('project_id')}] {al.get('reason_summary')}")
        sections.append("\n".join(i_lines))

    if anomalies:
        a_lines = [f"【🔍 Top {len(anomalies)} 疑似异常 / 差异显著项目及 SKU 根因】"]
        for anom in anomalies:
            a_lines.append(
                f"#{anom.get('rank')} [{anom.get('severity')}] {anom.get('project_id')} "
                f"(${anom.get('net_cost'):.2f} | DoD ${anom.get('dod_delta_net'):+.2f} | 7d均值 ${anom.get('avg_7d_net_cost'):.2f})\n"
                f"  • 异常判定: {anom.get('reason_summary')}"
            )
            for drv in (anom.get("top_sku_drivers") or [])[:3]:
                a_lines.append(
                    f"  • 根因 SKU: {drv.get('service')} / {drv.get('sku')} ({drv.get('location')}): "
                    f"当日 ${drv.get('target_net_cost'):.2f} (较7日均线 ${drv.get('delta_net_cost'):+.2f})"
                )
        sections.append("\n".join(a_lines))
    else:
        sections.append(
            "【✅ 异常波动检测结论】\n各 Project 日环比与 7 日滚动基线均处于正常波动区间内，未检测到疑似失控消费或折扣异常失效。"
        )

    if projects:
        p_lines = ["【📂 各 Project 每日净账单明细 Top 8】"]
        for p in projects[:8]:
            pct_s = f"{p.get('dod_pct_net'):+.1f}%" if p.get("dod_pct_net") is not None else "—"
            p_lines.append(
                f"• {p.get('project_id')}: 当日 ${p.get('net_cost'):.2f} "
                f"(DoD ${p.get('dod_delta_net'):+.2f} / {pct_s} | 7d均值 ${p.get('avg_7d_net_cost'):.2f} | MTD ${p.get('mtd_net_cost'):.2f})"
            )
        sections.append("\n".join(p_lines))

    elements.append(
        {"tag": "div", "text": {"tag": "plain_text", "content": "\n\n".join(sections)[:3800]}}
    )
    elements.append(
        {
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": "FinOps 提示：可在飞书直接询问「分析 2026-11-08 的账单异常根因」对任意历史日期进行回溯与 SKU 拆解。",
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


def build_finops_governance_feishu_card(
    report: FinOpsGovernanceReport | dict[str, Any],
) -> dict[str, Any]:
    """Render Feishu interactive card for FinOps Forecasting, ESR, Tag Hygiene, Top Resources & Waste."""
    d = report.to_dict() if isinstance(report, FinOpsGovernanceReport) else report
    b_status = str(d.get("budget_status") or "HEALTHY")
    waste_items = list(d.get("idle_waste_items") or [])
    waste_usd = float(d.get("estimated_monthly_waste_usd") or 0.0)

    if b_status == "EXCEEDED":
        template = "red"
        title = f"🚨 FinOps 预算超支预警与成本优化治理 ({d.get('as_of_date')})"
    elif b_status == "WARNING" or waste_usd >= 15.0 or float(d.get("unlabeled_spend_pct") or 0) >= 50.0:
        template = "orange"
        title = f"💡 FinOps 月度预测、折扣节省率与僵尸资源治理 ({d.get('as_of_date')})"
    else:
        template = "green"
        title = f"✅ FinOps 成本治理与预算健康报告 ({d.get('as_of_date')})"

    overview = (
        f"预算进度 ({d.get('days_elapsed')}/{d.get('days_in_month')} 天): "
        f"MTD ${d.get('mtd_net_cost_usd', 0.0):.2f} | 预测月末 (EOM) ${d.get('eom_forecast_net_usd', 0.0):.2f} "
        f"/ 预算 ${d.get('monthly_budget_usd', 0.0):.0f} ({d.get('forecast_budget_pct', 0.0):.1f}%)\n"
        f"综合节省率 (ESR): {d.get('effective_savings_rate_pct', 0.0):.1f}% "
        f"(当月累计节省 ${d.get('mtd_total_savings_usd', 0.0):.2f} | List ${d.get('mtd_list_cost_usd', 0.0):.2f})\n"
        f"近7日标签分账合规率: {d.get('label_compliance_pct', 0.0):.1f}% "
        f"(无标签黑盒支出 ${d.get('unlabeled_net_cost_7d_usd', 0.0):.2f} / {d.get('unlabeled_spend_pct', 0.0):.1f}%) | "
        f"预计可回收月度闲置浪费: ${waste_usd:.2f}/月"
    )
    elements: list[dict[str, Any]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": overview}},
        {"tag": "hr"},
    ]

    sections: list[str] = []
    creds = list(d.get("credit_breakdown") or [])
    if creds:
        c_lines = ["【💎 当月 CUD / 订阅权益 / 持续使用折扣抵扣结构】"]
        for c in creds[:4]:
            c_lines.append(
                f"• {c.get('credit_type')}: ${c.get('total_amount_usd', 0.0):.2f} "
                f"(占折扣总额 {c.get('share_of_savings_pct', 0.0):.1f}%)"
            )
        sections.append("\n".join(c_lines))

    if waste_items:
        w_lines = [f"【🗑️ 实时发现闲置/僵尸计费资源 ({len(waste_items)} 项 · 预计可省 ${waste_usd:.2f}/月)】"]
        for w in waste_items[:6]:
            w_lines.append(
                f"• [{w.get('project_id')} | {w.get('location')}] {w.get('resource_name')} "
                f"(约 ${w.get('estimated_monthly_waste_usd', 0.0):.2f}/月)\n"
                f"  ↳ {w.get('detail')}\n"
                f"  ↳ 清理建议: {w.get('cleanup_cli')}"
            )
        sections.append("\n".join(w_lines))
    else:
        sections.append("【✅ 闲置僵尸资源清查】\n全组织未发现未绑定外部静态 IP、孤儿磁盘或长期关机仍计费实例。")

    top_res = list(d.get("top_resources_7d") or [])
    if top_res:
        r_lines = ["【🔥 近 7 日单实例/资源净成本 Top 6】"]
        for r in top_res[:6]:
            lbl_tag = "已打标" if r.get("has_labels") else "⚠️无标签"
            r_lines.append(
                f"• [{r.get('project_id')}] {r.get('service')} · {r.get('resource_name')}: "
                f"${r.get('net_cost_7d', 0.0):.2f} ({lbl_tag})"
            )
        sections.append("\n".join(r_lines))

    elements.append(
        {"tag": "div", "text": {"tag": "plain_text", "content": "\n\n".join(sections)[:3800]}}
    )
    elements.append(
        {
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": "云管建议：对无标签高消费资源补充 env / owner / cost_center 标签；清理闲置静态 IP 前请确认无 DNS A 记录指向。",
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


_billing_service_instance: BillingFinOpsService | None = None


def get_billing_service() -> BillingFinOpsService:
    global _billing_service_instance
    if _billing_service_instance is None:
        _billing_service_instance = BillingFinOpsService()
    return _billing_service_instance


def set_billing_service(svc: BillingFinOpsService | None) -> None:
    global _billing_service_instance
    _billing_service_instance = svc
