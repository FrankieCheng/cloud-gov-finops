# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Partition-pruned BigQuery Billing Export query engine and FinOps statistical anomaly detector."""

from __future__ import annotations

import datetime
import math
import statistics
from collections import defaultdict
from typing import Any
from zoneinfo import ZoneInfo

from billing.models import AnomalyFinding, ProjectDailySpend, SkuDriver
from bot import config

BILLING_ACCOUNT_BUCKET = "_BILLING_ACCOUNT_LEVEL_"
BILLING_ACCOUNT_DISPLAY = "账单账户公共分摊 (CUD / Support)"


def resolve_settled_and_intraday_dates(tz_name: str = "Asia/Shanghai") -> tuple[str, str]:
    tz = ZoneInfo(tz_name)
    now_local = datetime.datetime.now(tz)
    today_str = now_local.date().isoformat()
    yesterday_str = (now_local.date() - datetime.timedelta(days=1)).isoformat()
    return yesterday_str, today_str


def _make_bq_client() -> Any:
    from google.cloud import bigquery
    from google.oauth2.credentials import Credentials

    tok = config.get_gcp_access_token()
    creds = Credentials(token=tok)
    return bigquery.Client(project=config.get_billing_bq_project(), credentials=creds)


def fetch_daily_project_series_live(
    tables: list[str],
    end_date_iso: str,
    tz_name: str = "Asia/Shanghai",
    lookback_days: int = 16,
) -> list[dict[str, Any]]:
    """Query daily Gross, Credits, and Net spend per project from BigQuery Billing Export."""
    from google.cloud import bigquery

    validated_tables = [config.validate_bq_table_id(t) for t in tables]
    clean_end = config.validate_iso_date(end_date_iso)
    end_dt = datetime.date.fromisoformat(clean_end)
    month_start = end_dt.replace(day=1)
    earliest_dt = min(end_dt - datetime.timedelta(days=lookback_days + 2), month_start)

    union_branches = " UNION ALL ".join(
        f"""
        SELECT
          usage_start_time,
          project.id AS proj_id,
          project.name AS proj_name,
          service.description AS svc_desc,
          currency,
          cost,
          IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0.0) AS credit_amt
        FROM `{tbl}`
        WHERE _PARTITIONTIME >= TIMESTAMP(@part_start)
          AND _PARTITIONTIME <= TIMESTAMP_ADD(TIMESTAMP(@part_end), INTERVAL 2 DAY)
        """
        for tbl in validated_tables
    )

    sql = f"""
    WITH raw AS (
      {union_branches}
    )
    SELECT
      CAST(DATE(usage_start_time, @tz) AS STRING) AS usage_day,
      IFNULL(proj_id, @acct_bucket) AS project_id,
      ANY_VALUE(IFNULL(proj_name, @acct_display)) AS project_name,
      ANY_VALUE(currency) AS currency,
      ROUND(SUM(cost), 6) AS gross_cost,
      ROUND(SUM(credit_amt), 6) AS credits_amount,
      ROUND(SUM(cost + credit_amt), 6) AS net_cost,
      COUNT(DISTINCT svc_desc) AS active_services
    FROM raw
    WHERE DATE(usage_start_time, @tz) >= DATE(@start_day)
      AND DATE(usage_start_time, @tz) <= DATE(@end_day)
    GROUP BY usage_day, project_id
    ORDER BY usage_day DESC, net_cost DESC
    """

    client = _make_bq_client()
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter(
                "part_start", "STRING", (earliest_dt - datetime.timedelta(days=2)).isoformat()
            ),
            bigquery.ScalarQueryParameter("part_end", "STRING", clean_end),
            bigquery.ScalarQueryParameter("tz", "STRING", tz_name),
            bigquery.ScalarQueryParameter("start_day", "STRING", earliest_dt.isoformat()),
            bigquery.ScalarQueryParameter("end_day", "STRING", clean_end),
            bigquery.ScalarQueryParameter("acct_bucket", "STRING", BILLING_ACCOUNT_BUCKET),
            bigquery.ScalarQueryParameter("acct_display", "STRING", BILLING_ACCOUNT_DISPLAY),
        ]
    )
    rows = client.query(sql, job_config=job_config).result()
    return [dict(r.items()) for r in rows]


def fetch_sku_drivers_live(
    tables: list[str],
    target_date_iso: str,
    project_ids: list[str],
    tz_name: str = "Asia/Shanghai",
) -> dict[str, list[SkuDriver]]:
    """Drill down into Service + SKU + Location drivers for anomalous projects."""
    if not project_ids:
        return {}
    from google.cloud import bigquery

    validated_tables = [config.validate_bq_table_id(t) for t in tables]
    clean_target = config.validate_iso_date(target_date_iso)
    t_dt = datetime.date.fromisoformat(clean_target)
    b_start = (t_dt - datetime.timedelta(days=7)).isoformat()
    b_end = (t_dt - datetime.timedelta(days=1)).isoformat()

    union_branches = " UNION ALL ".join(
        f"""
        SELECT
          usage_start_time,
          IFNULL(project.id, @acct_bucket) AS project_id,
          IFNULL(service.description, 'Unknown Service') AS service_desc,
          IFNULL(sku.description, 'Unknown SKU') AS sku_desc,
          IFNULL(location.location, 'global') AS loc,
          cost,
          IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0.0) AS credit_amt
        FROM `{tbl}`
        WHERE _PARTITIONTIME >= TIMESTAMP(@part_start)
          AND _PARTITIONTIME <= TIMESTAMP_ADD(TIMESTAMP(@target_day), INTERVAL 2 DAY)
        """
        for tbl in validated_tables
    )

    sql = f"""
    WITH raw AS (
      {union_branches}
    ),
    scoped AS (
      SELECT
        project_id,
        service_desc,
        sku_desc,
        loc,
        DATE(usage_start_time, @tz) AS u_day,
        cost,
        cost + credit_amt AS net_cost
      FROM raw
      WHERE project_id IN UNNEST(@proj_ids)
        AND DATE(usage_start_time, @tz) BETWEEN DATE(@b_start) AND DATE(@target_day)
    ),
    agg AS (
      SELECT
        project_id,
        service_desc,
        sku_desc,
        loc,
        SUM(IF(u_day = DATE(@target_day), net_cost, 0.0)) AS target_net,
        SUM(IF(u_day = DATE(@target_day), cost, 0.0)) AS target_gross,
        SAFE_DIVIDE(
          SUM(IF(u_day BETWEEN DATE(@b_start) AND DATE(@b_end), net_cost, 0.0)),
          7.0
        ) AS base_avg_net
      FROM scoped
      GROUP BY 1, 2, 3, 4
    )
    SELECT
      project_id,
      service_desc,
      sku_desc,
      loc,
      ROUND(target_net, 4) AS target_net,
      ROUND(target_gross, 4) AS target_gross,
      ROUND(IFNULL(base_avg_net, 0.0), 4) AS base_avg_net,
      ROUND(target_net - IFNULL(base_avg_net, 0.0), 4) AS delta_net
    FROM agg
    WHERE ABS(target_net - IFNULL(base_avg_net, 0.0)) >= 0.01 OR target_gross >= 0.1
    ORDER BY project_id, ABS(target_net - IFNULL(base_avg_net, 0.0)) DESC
    """

    client = _make_bq_client()
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter(
                "part_start", "STRING", (t_dt - datetime.timedelta(days=9)).isoformat()
            ),
            bigquery.ScalarQueryParameter("target_day", "STRING", clean_target),
            bigquery.ScalarQueryParameter("b_start", "STRING", b_start),
            bigquery.ScalarQueryParameter("b_end", "STRING", b_end),
            bigquery.ScalarQueryParameter("tz", "STRING", tz_name),
            bigquery.ScalarQueryParameter("acct_bucket", "STRING", BILLING_ACCOUNT_BUCKET),
            bigquery.ArrayQueryParameter("proj_ids", "STRING", project_ids),
        ]
    )
    rows = client.query(sql, job_config=job_config).result()
    out: dict[str, list[SkuDriver]] = defaultdict(list)
    for r in rows:
        pid = str(r["project_id"])
        if len(out[pid]) >= 4:
            continue
        out[pid].append(
            SkuDriver(
                service=str(r["service_desc"]),
                sku=str(r["sku_desc"]),
                location=str(r["loc"] or "global"),
                target_net_cost=float(r["target_net"] or 0.0),
                baseline_net_cost=float(r["base_avg_net"] or 0.0),
                delta_net_cost=float(r["delta_net"] or 0.0),
                target_gross_cost=float(r["target_gross"] or 0.0),
            )
        )
    return dict(out)


def get_mock_billing_series(end_date_iso: str) -> tuple[list[dict[str, Any]], dict[str, list[SkuDriver]]]:
    """Deterministic multi-project daily billing series with realistic anomalies for MOCK mode."""
    end_dt = datetime.date.fromisoformat(end_date_iso)
    series: list[dict[str, Any]] = []
    # T-1 = end_dt - 1 day (settled), T-0 = end_dt (intraday)
    settled_dt = end_dt - datetime.timedelta(days=1)

    for offset in range(10, -1, -1):
        d = end_dt - datetime.timedelta(days=offset)
        ds = d.isoformat()
        is_settled_day = d == settled_dt
        is_intraday = d == end_dt

        # Project 1: demo-core-prod spikes from ~$15.7 to $148.5 on settled_dt
        p1_net = 148.50 if is_settled_day else (6.20 if is_intraday else 15.70)
        series.append(
            {
                "usage_day": ds,
                "project_id": "demo-core-prod",
                "project_name": "demo-core-prod",
                "currency": "USD",
                "gross_cost": p1_net + 1.0,
                "credits_amount": -1.0,
                "net_cost": p1_net,
                "active_services": 18,
            }
        )
        # Project 2: demo-edge-svc steady ~$6.8, but intraday runaway $19.4 today!
        p2_net = 19.40 if is_intraday else 6.85
        series.append(
            {
                "usage_day": ds,
                "project_id": "demo-edge-svc",
                "project_name": "demo-edge-svc",
                "currency": "USD",
                "gross_cost": p2_net + 0.15,
                "credits_amount": -0.15,
                "net_cost": p2_net,
                "active_services": 8,
            }
        )
        # Project 3: dormant sandbox suddenly wakes up at $24.80 on settled_dt
        p3_net = 24.80 if is_settled_day else (0.0 if offset > 1 else 8.10)
        series.append(
            {
                "usage_day": ds,
                "project_id": "ai-sandbox-leak-09",
                "project_name": "ai-sandbox-leak-09",
                "currency": "USD",
                "gross_cost": p3_net,
                "credits_amount": 0.0,
                "net_cost": p3_net,
                "active_services": 2 if p3_net > 0 else 0,
            }
        )
        # Account-level CUD bucket: credit dropped on settled_dt causing net cost jump $4.29 -> $11.90
        acct_gross = 12.00
        acct_cred = -0.10 if is_settled_day else -7.71
        series.append(
            {
                "usage_day": ds,
                "project_id": BILLING_ACCOUNT_BUCKET,
                "project_name": BILLING_ACCOUNT_DISPLAY,
                "currency": "USD",
                "gross_cost": acct_gross,
                "credits_amount": acct_cred,
                "net_cost": round(acct_gross + acct_cred, 2),
                "active_services": 2,
            }
        )

    drivers = {
        "demo-core-prod": [
            SkuDriver(
                service="Vertex AI",
                sku="Gemini Online Prediction Output Tokens",
                location="global",
                target_net_cost=132.40,
                baseline_net_cost=1.80,
                delta_net_cost=130.60,
                target_gross_cost=132.40,
            ),
            SkuDriver(
                service="Cloud Run",
                sku="CPU Allocation Time (min-instances)",
                location="us-central1",
                target_net_cost=16.10,
                baseline_net_cost=13.90,
                delta_net_cost=2.20,
                target_gross_cost=17.10,
            ),
        ],
        "ai-sandbox-leak-09": [
            SkuDriver(
                service="Compute Engine",
                sku="NVIDIA L4 GPU running in Americas",
                location="us-central1",
                target_net_cost=24.80,
                baseline_net_cost=0.0,
                delta_net_cost=24.80,
                target_gross_cost=24.80,
            )
        ],
        BILLING_ACCOUNT_BUCKET: [
            SkuDriver(
                service="Compute Engine",
                sku="Commitment v1: Cpu in us-central1 (Credit Expired)",
                location="us-central1",
                target_net_cost=11.90,
                baseline_net_cost=4.29,
                delta_net_cost=7.61,
                target_gross_cost=12.00,
            )
        ],
    }
    return series, drivers


def analyze_daily_series(
    rows: list[dict[str, Any]],
    target_date_iso: str,
    intraday_date_iso: str = "",
    top_n: int = 5,
    min_delta_usd: float = 1.0,
    min_pct: float = 20.0,
) -> tuple[
    list[ProjectDailySpend],
    list[AnomalyFinding],
    list[AnomalyFinding],
    dict[str, float],
]:
    """Compute per-project metrics, MTD totals, Top-N anomalies, and intraday runaway alerts."""
    target_dt = datetime.date.fromisoformat(target_date_iso)
    prior_date_iso = (target_dt - datetime.timedelta(days=1)).isoformat()
    month_prefix = target_date_iso[:7]  # YYYY-MM

    by_proj_day: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    proj_meta: dict[str, tuple[str, str]] = {}

    for r in rows:
        pid = str(r.get("project_id") or BILLING_ACCOUNT_BUCKET)
        uday = str(r.get("usage_day") or "")
        if not uday:
            continue
        by_proj_day[pid][uday] = r
        proj_meta[pid] = (
            str(r.get("project_name") or pid),
            str(r.get("currency") or "USD"),
        )

    project_summaries: list[ProjectDailySpend] = []
    candidate_anomalies: list[AnomalyFinding] = []
    intraday_alerts: list[AnomalyFinding] = []

    total_gross = 0.0
    total_credits = 0.0
    total_net = 0.0
    prior_total_net = 0.0
    mtd_total_net = 0.0
    intraday_total_net = 0.0

    baseline_days = [
        (target_dt - datetime.timedelta(days=d)).isoformat() for d in range(1, 8)
    ]

    for pid, day_map in by_proj_day.items():
        pname, curr = proj_meta.get(pid, (pid, "USD"))
        t_row = day_map.get(target_date_iso, {})
        p_row = day_map.get(prior_date_iso, {})

        gross = float(t_row.get("gross_cost") or 0.0)
        creds = float(t_row.get("credits_amount") or 0.0)
        net = float(t_row.get("net_cost") or 0.0)
        act_svcs = int(t_row.get("active_services") or 0)

        prior_net = float(p_row.get("net_cost") or 0.0)
        prior_creds = float(p_row.get("credits_amount") or 0.0)

        mtd_proj = sum(
            float(v.get("net_cost") or 0.0)
            for d_key, v in day_map.items()
            if d_key.startswith(month_prefix) and d_key <= target_date_iso
        )

        hist_vals = [float(day_map[bd].get("net_cost") or 0.0) for bd in baseline_days if bd in day_map]
        if not hist_vals:
            hist_vals = [0.0]
        avg_7d = statistics.mean(hist_vals)
        std_7d = statistics.pstdev(hist_vals) if len(hist_vals) > 1 else 0.0
        denom = max(std_7d, max(0.20, 0.08 * abs(avg_7d)))
        z_score = round((net - avg_7d) / denom, 2)

        dod_delta = round(net - prior_net, 4)
        dod_pct = round((dod_delta / abs(prior_net)) * 100.0, 1) if abs(prior_net) >= 0.05 else None
        base_delta = round(net - avg_7d, 4)
        base_pct = round((base_delta / abs(avg_7d)) * 100.0, 1) if abs(avg_7d) >= 0.05 else None

        total_gross += gross
        total_credits += creds
        total_net += net
        prior_total_net += prior_net
        mtd_total_net += mtd_proj

        if abs(net) >= 0.001 or abs(prior_net) >= 0.01 or abs(mtd_proj) >= 0.01:
            project_summaries.append(
                ProjectDailySpend(
                    project_id=pid,
                    project_name=pname,
                    currency=curr,
                    gross_cost=round(gross, 4),
                    credits_amount=round(creds, 4),
                    net_cost=round(net, 4),
                    prior_day_net_cost=round(prior_net, 4),
                    dod_delta_net=dod_delta,
                    dod_pct_net=dod_pct,
                    avg_7d_net_cost=round(avg_7d, 4),
                    baseline_delta_net=base_delta,
                    baseline_pct_net=base_pct,
                    z_score=z_score,
                    mtd_net_cost=round(mtd_proj, 4),
                    active_services=act_svcs,
                )
            )

        # Evaluate multi-dimensional FinOps anomaly conditions
        max_abs_delta = max(abs(dod_delta), abs(base_delta))
        max_pct = max(abs(dod_pct or 0.0), abs(base_pct or 0.0))
        credit_shift = creds - prior_creds  # positive means fewer negative credits -> net spike!

        is_new_spend = avg_7d < 0.20 and net >= min_delta_usd
        is_credit_anomaly = credit_shift >= min_delta_usd and abs(creds) < abs(prior_creds) * 0.6
        is_spike_or_drop = (
            max_abs_delta >= min_delta_usd and (max_pct >= min_pct or abs(z_score) >= 2.2)
        )

        if is_new_spend or is_credit_anomaly or is_spike_or_drop:
            if is_new_spend:
                atype = "NEW_SPEND"
                reason = f"此前 7 日均值接近 $0（${avg_7d:.2f}），当日突增消费 ${net:.2f}（疑似新建或遗忘沙箱资源）"
            elif is_credit_anomaly and dod_delta > 0:
                atype = "CREDIT_CHANGE"
                reason = (
                    f"折扣/抵扣额由 ${prior_creds:.2f} 缩减至 ${creds:.2f}，导致净支出环比上涨 +${dod_delta:.2f}"
                )
            elif base_delta >= 0 and dod_delta >= 0:
                atype = "COST_SPIKE"
                pct_str = f"+{dod_pct:.1f}%" if dod_pct is not None else "突增"
                reason = (
                    f"净成本 ${net:.2f} 较前一日（${prior_net:.2f}）上涨 +${dod_delta:.2f} ({pct_str})，"
                    f"偏离 7 日基线均值（${avg_7d:.2f}）Z-Score={z_score:+.1f}"
                )
            else:
                atype = "COST_DROP"
                pct_str = f"{dod_pct:+.1f}%" if dod_pct is not None else "骤降"
                reason = (
                    f"净成本 ${net:.2f} 较前一日（${prior_net:.2f}）变动 ${dod_delta:+.2f} ({pct_str})，"
                    f"偏离 7 日均值（${avg_7d:.2f}）Z-Score={z_score:+.1f}（请确认是否有业务缩容或数据延迟）"
                )

            score = round(
                abs(base_delta) * (1.0 + min(abs(z_score), 10.0) * 0.35) + abs(dod_delta) * 0.5,
                2,
            )
            if abs(z_score) >= 4.0 or max_abs_delta >= 25.0 or (dod_pct or 0.0) >= 100.0:
                sev = "CRITICAL"
            elif abs(z_score) >= 2.5 or max_abs_delta >= 5.0 or max_pct >= 40.0:
                sev = "HIGH"
            else:
                sev = "MEDIUM"

            candidate_anomalies.append(
                AnomalyFinding(
                    rank=0,
                    severity=sev,
                    anomaly_type=atype,
                    project_id=pid,
                    project_name=pname,
                    usage_date=target_date_iso,
                    currency=curr,
                    net_cost=round(net, 2),
                    gross_cost=round(gross, 2),
                    prior_day_net_cost=round(prior_net, 2),
                    avg_7d_net_cost=round(avg_7d, 2),
                    dod_delta_net=round(dod_delta, 2),
                    dod_pct_net=dod_pct,
                    baseline_delta_net=round(base_delta, 2),
                    baseline_pct_net=base_pct,
                    z_score=z_score,
                    anomaly_score=score,
                    reason_summary=reason,
                )
            )

        # Intraday T-0 runaway check
        if intraday_date_iso and intraday_date_iso != target_date_iso:
            intra_row = day_map.get(intraday_date_iso, {})
            intra_net = float(intra_row.get("net_cost") or 0.0)
            intra_gross = float(intra_row.get("gross_cost") or 0.0)
            intraday_total_net += intra_net
            ref_full_day = max(net, avg_7d)
            if (
                intra_net - ref_full_day >= min_delta_usd
                and (ref_full_day < 0.20 or intra_net >= ref_full_day * 1.25)
            ):
                intra_delta = round(intra_net - ref_full_day, 2)
                intra_pct = (
                    round((intra_delta / ref_full_day) * 100.0, 1) if ref_full_day >= 0.05 else None
                )
                intraday_alerts.append(
                    AnomalyFinding(
                        rank=0,
                        severity="CRITICAL",
                        anomaly_type="INTRADAY_SPIKE",
                        project_id=pid,
                        project_name=pname,
                        usage_date=intraday_date_iso,
                        currency=curr,
                        net_cost=round(intra_net, 2),
                        gross_cost=round(intra_gross, 2),
                        prior_day_net_cost=round(net, 2),
                        avg_7d_net_cost=round(avg_7d, 2),
                        dod_delta_net=round(intra_net - net, 2),
                        dod_pct_net=intra_pct,
                        baseline_delta_net=round(intra_net - avg_7d, 2),
                        baseline_pct_net=intra_pct,
                        z_score=round(intra_delta / max(0.5, 0.1 * max(1.0, ref_full_day)), 2),
                        anomaly_score=round(abs(intra_delta) * 2.0, 2),
                        reason_summary=(
                            f"⚡ 当日盘中未完结账单已达 ${intra_net:.2f}，超过昨日全天（${net:.2f}）+${intra_delta:.2f}，存在实时资源暴涨！"
                        ),
                    )
                )

    project_summaries.sort(key=lambda p: p.net_cost, reverse=True)
    candidate_anomalies.sort(key=lambda a: a.anomaly_score, reverse=True)
    selected_anomalies = candidate_anomalies[: max(1, top_n)]
    for idx, item in enumerate(selected_anomalies, 1):
        item.rank = idx

    intraday_alerts.sort(key=lambda a: a.anomaly_score, reverse=True)
    for idx, item in enumerate(intraday_alerts, 1):
        item.rank = idx

    totals = {
        "total_gross_cost": round(total_gross, 2),
        "total_credits": round(total_credits, 2),
        "total_net_cost": round(total_net, 2),
        "prior_day_total_net_cost": round(prior_total_net, 2),
        "total_dod_delta_net": round(total_net - prior_total_net, 2),
        "total_dod_pct_net": (
            round(((total_net - prior_total_net) / abs(prior_total_net)) * 100.0, 1)
            if abs(prior_total_net) >= 0.05 and not math.isnan(total_net)
            else None
        ),
        "mtd_total_net_cost": round(mtd_total_net, 2),
        "intraday_total_net_cost": round(intraday_total_net, 2),
    }
    return project_summaries, selected_anomalies, intraday_alerts, totals
