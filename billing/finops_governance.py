# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Enterprise FinOps Governance: EOM Forecasting, ESR/Credits, Tag Hygiene, Top Resources & Idle Waste."""

from __future__ import annotations

import calendar
import concurrent.futures
import datetime
import logging
import urllib.error
import urllib.parse
from typing import Any

from billing.analyzer import BILLING_ACCOUNT_BUCKET, _make_bq_client
from billing.models import (
    CreditCategorySummary,
    FinOpsGovernanceReport,
    IdleWasteItem,
    ProjectLabelCompliance,
    ResourceCostItem,
)
from bot import config
from quota.scanner import _gcp_get_json, discover_org_projects_live

logger = logging.getLogger(__name__)


def compute_eom_forecast_and_budget(
    as_of_date_iso: str,
    mtd_net_cost: float,
    avg_7d_daily_net: float,
    monthly_budget_usd: float,
) -> dict[str, Any]:
    """Compute blended month-end forecast (`MTD + remaining_days * run_rate`) and budget burn status."""
    dt = datetime.date.fromisoformat(config.validate_iso_date(as_of_date_iso))
    days_in_month = calendar.monthrange(dt.year, dt.month)[1]
    days_elapsed = max(1, dt.day)
    remaining_days = max(0, days_in_month - days_elapsed)

    mtd_daily_avg = mtd_net_cost / float(days_elapsed)
    effective_run_rate = (
        0.65 * avg_7d_daily_net + 0.35 * mtd_daily_avg
        if avg_7d_daily_net > 0
        else mtd_daily_avg
    )
    eom_forecast = round(max(mtd_net_cost, mtd_net_cost + remaining_days * effective_run_rate), 2)

    budget = max(1.0, float(monthly_budget_usd))
    budget_util_pct = round((mtd_net_cost / budget) * 100.0, 1)
    forecast_pct = round((eom_forecast / budget) * 100.0, 1)

    if mtd_net_cost >= budget or forecast_pct >= 100.0:
        status = "EXCEEDED"
    elif forecast_pct >= 85.0 or budget_util_pct >= 80.0:
        status = "WARNING"
    else:
        status = "HEALTHY"

    return {
        "days_elapsed": days_elapsed,
        "days_in_month": days_in_month,
        "eom_forecast_net_usd": eom_forecast,
        "budget_utilization_pct": budget_util_pct,
        "forecast_budget_pct": forecast_pct,
        "budget_status": status,
    }


def fetch_esr_labels_and_resources_live(
    tables: list[str],
    as_of_date_iso: str,
    tz_name: str = "Asia/Shanghai",
    top_resources_limit: int = 10,
) -> dict[str, Any]:
    """Query BigQuery Billing Export for MTD ESR/Credits, 7d Label Compliance, and 7d Top Resources."""
    from google.cloud import bigquery

    validated_tables = [config.validate_bq_table_id(t) for t in tables]
    clean_end = config.validate_iso_date(as_of_date_iso)
    end_dt = datetime.date.fromisoformat(clean_end)
    month_start = end_dt.replace(day=1)
    seven_d_start = end_dt - datetime.timedelta(days=6)
    earliest_dt = min(month_start, seven_d_start)
    part_start = (earliest_dt - datetime.timedelta(days=2)).isoformat()

    client = _make_bq_client()
    common_params = [
        bigquery.ScalarQueryParameter("part_start", "STRING", part_start),
        bigquery.ScalarQueryParameter("end_day", "STRING", clean_end),
        bigquery.ScalarQueryParameter("month_start", "STRING", month_start.isoformat()),
        bigquery.ScalarQueryParameter("seven_d_start", "STRING", seven_d_start.isoformat()),
        bigquery.ScalarQueryParameter("tz", "STRING", tz_name),
        bigquery.ScalarQueryParameter("acct_bucket", "STRING", BILLING_ACCOUNT_BUCKET),
    ]

    # Query 1: MTD List vs Gross vs Net + Credit Type Breakdown
    esr_branches = " UNION ALL ".join(
        f"""
        SELECT
          DATE(usage_start_time, @tz) AS u_day,
          IFNULL(cost_at_list, cost) AS list_cost,
          cost,
          credits
        FROM `{tbl}`
        WHERE _PARTITIONTIME >= TIMESTAMP(@part_start)
          AND _PARTITIONTIME <= TIMESTAMP_ADD(TIMESTAMP(@end_day), INTERVAL 2 DAY)
        """
        for tbl in validated_tables
    )
    esr_sql = f"""
    WITH base AS (
      SELECT * FROM ({esr_branches})
      WHERE u_day BETWEEN DATE(@month_start) AND DATE(@end_day)
    ),
    totals AS (
      SELECT
        ROUND(SUM(list_cost), 4) AS mtd_list_cost,
        ROUND(SUM(cost), 4) AS mtd_gross_cost,
        ROUND(SUM(cost + IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0.0)), 4) AS mtd_net_cost
      FROM base
    ),
    cred_agg AS (
      SELECT
        IFNULL(c.type, 'DISCOUNT') AS credit_type,
        ROUND(SUM(c.amount), 4) AS amt
      FROM base, UNNEST(credits) c
      GROUP BY 1
    )
    SELECT
      (SELECT mtd_list_cost FROM totals) AS mtd_list_cost,
      (SELECT mtd_gross_cost FROM totals) AS mtd_gross_cost,
      (SELECT mtd_net_cost FROM totals) AS mtd_net_cost,
      ARRAY(
        SELECT AS STRUCT credit_type, amt
        FROM cred_agg
        WHERE ABS(amt) >= 0.01
        ORDER BY amt ASC
      ) AS credits_by_type
    """
    esr_row = next(
        iter(client.query(esr_sql, job_config=bigquery.QueryJobConfig(query_parameters=common_params)).result()),
        None,
    )
    mtd_list = float((esr_row["mtd_list_cost"] if esr_row else 0.0) or 0.0)
    mtd_gross = float((esr_row["mtd_gross_cost"] if esr_row else 0.0) or 0.0)
    mtd_net = float((esr_row["mtd_net_cost"] if esr_row else 0.0) or 0.0)
    mtd_list = max(mtd_list, mtd_gross)
    total_savings = round(max(0.0, mtd_list - mtd_net), 2)
    esr_pct = round((total_savings / mtd_list) * 100.0, 1) if mtd_list > 0.05 else 0.0

    credit_items: list[CreditCategorySummary] = []
    raw_creds = list(esr_row["credits_by_type"] or []) if esr_row else []
    abs_cred_sum = sum(abs(float(c["amt"] or 0.0)) for c in raw_creds) or 1.0
    for c in raw_creds:
        amt = round(float(c["amt"] or 0.0), 2)
        credit_items.append(
            CreditCategorySummary(
                credit_type=str(c["credit_type"]),
                total_amount_usd=amt,
                share_of_savings_pct=round((abs(amt) / abs_cred_sum) * 100.0, 1),
            )
        )

    # Query 2: 7-day Label Compliance & Top Individual Resources (single scan)
    res_branches = " UNION ALL ".join(
        f"""
        SELECT
          DATE(usage_start_time, @tz) AS u_day,
          IFNULL(project.id, @acct_bucket) AS project_id,
          IFNULL(service.description, 'Unknown') AS svc,
          IFNULL(location.location, 'global') AS loc,
          COALESCE(NULLIF(resource.name, ''), NULLIF(resource.global_name, '')) AS res_id,
          (ARRAY_LENGTH(labels) > 0 OR ARRAY_LENGTH(tags) > 0) AS is_labeled,
          cost,
          cost + IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0.0) AS net_cost
        FROM `{tbl}`
        WHERE _PARTITIONTIME >= TIMESTAMP(@part_start)
          AND _PARTITIONTIME <= TIMESTAMP_ADD(TIMESTAMP(@end_day), INTERVAL 2 DAY)
        """
        for tbl in validated_tables
    )
    gov_sql = f"""
    WITH w7 AS (
      SELECT * FROM ({res_branches})
      WHERE u_day BETWEEN DATE(@seven_d_start) AND DATE(@end_day)
    ),
    proj_lbl AS (
      SELECT
        project_id,
        ROUND(SUM(net_cost), 4) AS net_7d,
        ROUND(SUM(IF(NOT is_labeled AND project_id != @acct_bucket, net_cost, 0.0)), 4) AS unlbl_7d
      FROM w7
      GROUP BY 1
    ),
    top_res AS (
      SELECT
        project_id,
        svc,
        res_id,
        ANY_VALUE(loc) AS loc,
        LOGICAL_OR(is_labeled) AS has_labels,
        ROUND(SUM(net_cost), 4) AS net_7d,
        ROUND(SUM(cost), 4) AS gross_7d
      FROM w7
      WHERE res_id IS NOT NULL
      GROUP BY 1, 2, 3
      HAVING net_7d >= 0.25
      ORDER BY net_7d DESC
      LIMIT {int(max(1, min(top_resources_limit, 25)))}
    )
    SELECT
      ARRAY(SELECT AS STRUCT * FROM proj_lbl WHERE net_7d >= 0.05 ORDER BY unlbl_7d DESC) AS proj_labels,
      ARRAY(SELECT AS STRUCT * FROM top_res ORDER BY net_7d DESC) AS top_resources
    """
    gov_row = next(
        iter(client.query(gov_sql, job_config=bigquery.QueryJobConfig(query_parameters=common_params)).result()),
        None,
    )

    proj_gaps: list[ProjectLabelCompliance] = []
    net_7d_allocatable = 0.0
    unlbl_7d_total = 0.0
    for pl in (gov_row["proj_labels"] or []) if gov_row else []:
        pid = str(pl["project_id"])
        n7 = round(float(pl["net_7d"] or 0.0), 2)
        u7 = round(max(0.0, float(pl["unlbl_7d"] or 0.0)), 2)
        if pid != BILLING_ACCOUNT_BUCKET and n7 > 0:
            net_7d_allocatable += n7
            unlbl_7d_total += u7
            pct = round(min(100.0, (u7 / n7) * 100.0), 1)
            if u7 >= 0.50:
                proj_gaps.append(
                    ProjectLabelCompliance(
                        project_id=pid,
                        net_cost_7d=n7,
                        unlabeled_net_cost_7d=u7,
                        unlabeled_pct=pct,
                    )
                )

    unlbl_pct = (
        round(min(100.0, (unlbl_7d_total / net_7d_allocatable) * 100.0), 1)
        if net_7d_allocatable > 0.05
        else 0.0
    )

    top_res_items: list[ResourceCostItem] = []
    for tr in (gov_row["top_resources"] or []) if gov_row else []:
        raw_res = str(tr["res_id"] or "")
        short_res = raw_res.split("/instances/")[-1] if "/instances/" in raw_res else raw_res
        if len(short_res) > 68:
            short_res = "..." + short_res[-65:]
        top_res_items.append(
            ResourceCostItem(
                project_id=str(tr["project_id"]),
                service=str(tr["svc"]),
                resource_name=short_res,
                location=str(tr["loc"] or "global"),
                net_cost_7d=round(float(tr["net_7d"] or 0.0), 2),
                gross_cost_7d=round(float(tr["gross_7d"] or 0.0), 2),
                has_labels=bool(tr["has_labels"]),
            )
        )

    return {
        "mtd_list_cost_usd": round(mtd_list, 2),
        "mtd_gross_cost_usd": round(mtd_gross, 2),
        "mtd_net_cost_usd": round(mtd_net, 2),
        "mtd_total_savings_usd": total_savings,
        "effective_savings_rate_pct": esr_pct,
        "credit_breakdown": credit_items,
        "net_cost_7d_usd": round(net_7d_allocatable, 2),
        "unlabeled_net_cost_7d_usd": round(unlbl_7d_total, 2),
        "unlabeled_spend_pct": unlbl_pct,
        "label_compliance_pct": round(max(0.0, 100.0 - unlbl_pct), 1),
        "project_label_gaps": proj_gaps,
        "top_resources_7d": top_res_items,
    }


def _scan_single_project_waste(project_id: str, token: str) -> list[IdleWasteItem]:
    """Scan one GCP project for idle external IPs, unattached disks, stopped VMs, and >90d snapshots."""
    findings: list[IdleWasteItem] = []
    p_enc = urllib.parse.quote(project_id)

    # 1. Idle Reserved External Static IPv4 Addresses (~$7.30/mo each when unattached)
    try:
        addr_data = _gcp_get_json(
            f"https://compute.googleapis.com/compute/v1/projects/{p_enc}/aggregated/addresses?maxResults=150",
            token,
            timeout=15,
        )
        for scope_key, sc in (addr_data.get("items") or {}).items():
            for ad in sc.get("addresses") or []:
                if (
                    str(ad.get("addressType") or "") == "EXTERNAL"
                    and str(ad.get("status") or "") == "RESERVED"
                    and not ad.get("users")
                ):
                    name = str(ad.get("name") or "unnamed-ip")
                    ip = str(ad.get("address") or "")
                    loc = "global" if scope_key == "global" else scope_key.replace("regions/", "")
                    loc_flag = "--global" if loc == "global" else f"--region={loc}"
                    findings.append(
                        IdleWasteItem(
                            project_id=project_id,
                            category="IDLE_EXTERNAL_IP",
                            resource_name=f"{name} ({ip})" if ip else name,
                            location=loc,
                            detail="已保留但未绑定任何实例/负载均衡器的外部静态 IPv4 地址（$0.01/小时持续计费）",
                            estimated_monthly_waste_usd=7.30,
                            cleanup_cli=f"gcloud compute addresses delete {name} {loc_flag} --project={project_id}",
                        )
                    )
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404):
            return findings
    except Exception as exc:
        logger.debug("Address waste scan skipped on %s: %s", project_id, type(exc).__name__)

    # 2. Unattached Persistent Disks
    try:
        disk_data = _gcp_get_json(
            f"https://compute.googleapis.com/compute/v1/projects/{p_enc}/aggregated/disks?maxResults=150",
            token,
            timeout=15,
        )
        for scope_key, sc in (disk_data.get("items") or {}).items():
            for dk in sc.get("disks") or []:
                if not dk.get("users"):
                    name = str(dk.get("name") or "orphan-disk")
                    size_gb = float(dk.get("sizeGb") or 10.0)
                    dtype = str(dk.get("type") or "").split("/")[-1]
                    rate = 0.17 if "ssd" in dtype or "extreme" in dtype else (0.10 if "balanced" in dtype else 0.04)
                    est = round(size_gb * rate, 2)
                    loc = scope_key.replace("zones/", "").replace("regions/", "")
                    loc_flag = f"--zone={loc}" if "-" in loc and loc[-1].isalpha() else f"--region={loc}"
                    findings.append(
                        IdleWasteItem(
                            project_id=project_id,
                            category="UNATTACHED_DISK",
                            resource_name=name,
                            location=loc,
                            detail=f"未挂载孤儿磁盘 ({int(size_gb)} GB {dtype or 'pd'})",
                            estimated_monthly_waste_usd=est,
                            cleanup_cli=f"gcloud compute disks delete {name} {loc_flag} --project={project_id}",
                        )
                    )
    except Exception as exc:
        logger.debug("Disk waste scan skipped on %s: %s", project_id, type(exc).__name__)

    # 3. Stopped (`TERMINATED`) VMs still holding boot/attached disks
    try:
        inst_data = _gcp_get_json(
            f"https://compute.googleapis.com/compute/v1/projects/{p_enc}/aggregated/instances?maxResults=150",
            token,
            timeout=15,
        )
        for scope_key, sc in (inst_data.get("items") or {}).items():
            for vm in sc.get("instances") or []:
                if str(vm.get("status") or "") == "TERMINATED":
                    name = str(vm.get("name") or "stopped-vm")
                    zone = scope_key.replace("zones/", "")
                    disks = vm.get("disks") or []
                    total_gb = sum(float(d.get("diskSizeGb") or 20.0) for d in disks) or 20.0
                    est = round(total_gb * 0.08, 2)
                    findings.append(
                        IdleWasteItem(
                            project_id=project_id,
                            category="STOPPED_VM",
                            resource_name=name,
                            location=zone,
                            detail=f"已关机 (TERMINATED) 实例仍挂载 {int(total_gb)} GB 持久化磁盘持续计费",
                            estimated_monthly_waste_usd=est,
                            cleanup_cli=f"gcloud compute instances delete {name} --zone={zone} --project={project_id}",
                        )
                    )
    except Exception as exc:
        logger.debug("Instance waste scan skipped on %s: %s", project_id, type(exc).__name__)

    # 4. Aging Disk Snapshots (>90 days old)
    try:
        snap_data = _gcp_get_json(
            f"https://compute.googleapis.com/compute/v1/projects/{p_enc}/global/snapshots?maxResults=150",
            token,
            timeout=15,
        )
        cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=90)
        old_snaps: list[tuple[str, float]] = []
        for sn in snap_data.get("items") or []:
            ts_raw = str(sn.get("creationTimestamp") or "")
            try:
                created = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            if created < cutoff:
                gb = float(sn.get("storageBytes") or 0.0) / (1024**3)
                old_snaps.append((str(sn.get("name") or "snap"), max(gb, 1.0)))
        if old_snaps:
            tot_gb = sum(g for _, g in old_snaps)
            est = round(max(0.50, tot_gb * 0.026), 2)
            sample = old_snaps[0][0]
            findings.append(
                IdleWasteItem(
                    project_id=project_id,
                    category="AGING_SNAPSHOT",
                    resource_name=f"{len(old_snaps)} 个超 90 天历史快照 (如 {sample})",
                    location="global",
                    detail=f"共 {len(old_snaps)} 个超过 90 天的历史磁盘快照（约 {tot_gb:.1f} GB）",
                    estimated_monthly_waste_usd=est,
                    cleanup_cli=f"gcloud compute snapshots delete {sample} --project={project_id}",
                )
            )
    except Exception as exc:
        logger.debug("Snapshot waste scan skipped on %s: %s", project_id, type(exc).__name__)

    return findings


def scan_idle_waste_live(org_id: str, seed_projects: list[str]) -> list[IdleWasteItem]:
    """Scan all active Org projects concurrently for idle/zombie billable resources."""
    token = config.get_gcp_access_token()
    projects = list(seed_projects)
    if org_id:
        for dp in discover_org_projects_live(org_id, token):
            if dp not in projects:
                projects.append(dp)

    items: list[IdleWasteItem] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(_scan_single_project_waste, p, token): p for p in projects}
        for fut in concurrent.futures.as_completed(futs):
            try:
                items.extend(fut.result())
            except Exception as exc:
                logger.debug("Waste worker error: %s", type(exc).__name__)

    items.sort(key=lambda x: x.estimated_monthly_waste_usd, reverse=True)
    return items


def get_mock_finops_governance(
    as_of_date_iso: str, monthly_budget_usd: float = 1000.0
) -> FinOpsGovernanceReport:
    """Deterministic FinOps Governance fixture for MOCK unit testing."""
    fc = compute_eom_forecast_and_budget(
        as_of_date_iso=as_of_date_iso,
        mtd_net_cost=642.50,
        avg_7d_daily_net=44.20,
        monthly_budget_usd=monthly_budget_usd,
    )
    waste = [
        IdleWasteItem(
            project_id="demo-core-prod",
            category="IDLE_EXTERNAL_IP",
            resource_name="lb-ipv4-vip-1 (203.0.113.10)",
            location="global",
            detail="已保留但未绑定的外部静态 IPv4 地址",
            estimated_monthly_waste_usd=7.30,
            cleanup_cli="gcloud compute addresses delete lb-ipv4-vip-1 --global --project=demo-core-prod",
        ),
        IdleWasteItem(
            project_id="demo-edge-svc",
            category="UNATTACHED_DISK",
            resource_name="orphan-ssd-data-01",
            location="us-central1-a",
            detail="未挂载孤儿磁盘 (200 GB pd-ssd)",
            estimated_monthly_waste_usd=34.00,
            cleanup_cli="gcloud compute disks delete orphan-ssd-data-01 --zone=us-central1-a --project=demo-edge-svc",
        ),
    ]
    return FinOpsGovernanceReport(
        generated_at=f"{as_of_date_iso}T00:00:00Z",
        mode="MOCK",
        as_of_date=as_of_date_iso,
        monthly_budget_usd=monthly_budget_usd,
        mtd_net_cost_usd=642.50,
        avg_7d_daily_net_usd=44.20,
        days_elapsed=fc["days_elapsed"],
        days_in_month=fc["days_in_month"],
        eom_forecast_net_usd=fc["eom_forecast_net_usd"],
        budget_utilization_pct=fc["budget_utilization_pct"],
        forecast_budget_pct=fc["forecast_budget_pct"],
        budget_status=fc["budget_status"],
        mtd_list_cost_usd=740.00,
        mtd_gross_cost_usd=712.50,
        mtd_total_savings_usd=97.50,
        effective_savings_rate_pct=13.2,
        credit_breakdown=[
            CreditCategorySummary(
                credit_type="SUBSCRIPTION_BENEFIT",
                total_amount_usd=-52.00,
                share_of_savings_pct=74.3,
            ),
            CreditCategorySummary(
                credit_type="SUSTAINED_USAGE_DISCOUNT",
                total_amount_usd=-18.00,
                share_of_savings_pct=25.7,
            ),
        ],
        net_cost_7d_usd=309.40,
        unlabeled_net_cost_7d_usd=182.50,
        unlabeled_spend_pct=59.0,
        label_compliance_pct=41.0,
        project_label_gaps=[
            ProjectLabelCompliance(
                project_id="demo-core-prod",
                net_cost_7d=190.00,
                unlabeled_net_cost_7d=135.00,
                unlabeled_pct=71.1,
            )
        ],
        top_resources_7d=[
            ResourceCostItem(
                project_id="demo-core-prod",
                service="Compute Engine",
                resource_name="vm-model-armor-test",
                location="us-central1",
                net_cost_7d=32.10,
                gross_cost_7d=34.00,
                has_labels=False,
            )
        ],
        idle_waste_items=waste,
        estimated_monthly_waste_usd=round(sum(w.estimated_monthly_waste_usd for w in waste), 2),
    )
