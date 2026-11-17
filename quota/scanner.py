# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Dual-layer (Project + Organization) Quota Scanner using Cloud Quotas, Compute, and Monitoring APIs."""

from __future__ import annotations

import datetime
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from bot import config
from quota.models import OrgQuotaPreference, QuotaExceededEvent, QuotaMetricItem, QuotaRiskLevel

logger = logging.getLogger(__name__)

ORG_QUOTA_SERVICES = (
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "orgpolicy.googleapis.com",
    "cloudbilling.googleapis.com",
    "accesscontextmanager.googleapis.com",
)


def classify_risk(
    pct: float, critical_pct: float = 90.0, warning_pct: float = 80.0
) -> QuotaRiskLevel:
    if pct >= critical_pct:
        return QuotaRiskLevel.CRITICAL
    if pct >= warning_pct:
        return QuotaRiskLevel.WARNING
    return QuotaRiskLevel.HEALTHY


def build_quota_increase_cli(
    scope_type: str,
    scope_id: str,
    service: str,
    quota_id: str,
    region: str,
    limit: float,
) -> str:
    """Generate a ready-to-run `gcloud alpha quotas preferences create` CLI command for 1.5x headroom."""
    import math

    target_val = max(int(limit) + 1, int(math.ceil(limit * 1.5)))
    scope_flag = (
        f"--organization={scope_id}" if scope_type == "ORGANIZATION" else f"--project={scope_id}"
    )
    dim_flag = f" --dimensions=region={region}" if region and region != "global" else ""
    safe_pref_id = f"bump-{quota_id.lower().replace('_', '-')[:28]}-{region.replace('-', '')[:8]}"
    return (
        f"gcloud alpha quotas preferences create --service={service} "
        f"--quota-id={quota_id} --preferred-value={target_val} "
        f"{scope_flag}{dim_flag} --preference-id={safe_pref_id}"
    )


def build_quota_recommendation(
    scope_type: str, scope_id: str, service: str, quota_id: str, region: str, pct: float, limit: float = 0.0
) -> str:
    if pct >= 90.0:
        cli_hint = (
            f" 提额命令: `{build_quota_increase_cli(scope_type, scope_id, service, quota_id, region, limit)}`"
            if limit > 0
            else ""
        )
        if scope_type == "ORGANIZATION":
            return (
                f"组织级配额已达 {pct:.1f}% 红线！请立即提交提额申请或清理无用资源。{cli_hint}"
            )
        return (
            f"项目 `{scope_id}` 在 `{region}` 的 `{quota_id}` 使用率已达 {pct:.1f}%（≥90%），随时可能触发扩容限流。{cli_hint}"
        )
    if pct >= 80.0:
        return f"使用率已达 {pct:.1f}% 预警水位，建议提前在业务高峰前规划提额（服务: {service}）。"
    return "水位正常"


def _gcp_get_json(url: str, token: str, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}


def discover_org_projects_live(org_id: str, token: str) -> list[str]:
    """Discover active projects visible to the caller via Cloud Resource Manager v3."""
    discovered: list[str] = []
    url = "https://cloudresourcemanager.googleapis.com/v3/projects:search?pageSize=100"
    try:
        data = _gcp_get_json(url, token, timeout=15)
        for proj in data.get("projects") or []:
            if str(proj.get("state") or "") != "ACTIVE":
                continue
            pid = str(proj.get("projectId") or "").strip()
            if pid and pid not in discovered:
                discovered.append(pid)
    except Exception as exc:
        logger.debug("CRM project discovery skipped: %s", type(exc).__name__)
    return discovered


def scan_compute_quotas_live(
    project_id: str,
    token: str,
    critical_pct: float = 90.0,
    warning_pct: float = 80.0,
) -> list[QuotaMetricItem]:
    """Fetch Compute Engine project-wide and regional quotas (gracefully skipping if Compute API disabled)."""
    items: list[QuotaMetricItem] = []
    proj_url = f"https://compute.googleapis.com/compute/v1/projects/{urllib.parse.quote(project_id)}"
    try:
        proj_data = _gcp_get_json(proj_url, token, timeout=15)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        if exc.code == 404 or "accessNotConfigured" in body or "has not been used" in body:
            return []
        raise

    for q in proj_data.get("quotas") or []:
        limit = float(q.get("limit") or 0.0)
        usage = float(q.get("usage") or 0.0)
        if limit <= 0:
            continue
        pct = round((usage / limit) * 100.0, 2)
        if usage <= 0 and pct < warning_pct:
            continue
        metric_code = str(q.get("metric") or "UNKNOWN")
        risk = classify_risk(pct, critical_pct, warning_pct)
        inc_cli = (
            build_quota_increase_cli("PROJECT", project_id, "compute.googleapis.com", metric_code, "global", limit)
            if pct >= warning_pct
            else ""
        )
        items.append(
            QuotaMetricItem(
                scope_type="PROJECT",
                scope_id=project_id,
                service="compute.googleapis.com",
                quota_id=metric_code,
                metric=f"compute.googleapis.com/{metric_code.lower()}",
                display_name=f"Compute Global · {metric_code}",
                region="global",
                usage=usage,
                limit=limit,
                utilization_pct=pct,
                risk_level=risk,
                recommendation=build_quota_recommendation(
                    "PROJECT", project_id, "compute.googleapis.com", metric_code, "global", pct, limit
                ),
                quota_increase_cli=inc_cli,
            )
        )

    reg_url = f"https://compute.googleapis.com/compute/v1/projects/{urllib.parse.quote(project_id)}/regions?maxResults=50"
    try:
        reg_data = _gcp_get_json(reg_url, token, timeout=20)
        for reg in reg_data.get("items") or []:
            rname = str(reg.get("name") or "unknown")
            for q in reg.get("quotas") or []:
                limit = float(q.get("limit") or 0.0)
                usage = float(q.get("usage") or 0.0)
                if limit <= 0 or usage <= 0:
                    continue
                pct = round((usage / limit) * 100.0, 2)
                metric_code = str(q.get("metric") or "UNKNOWN")
                qid = f"{metric_code}-per-region"
                risk = classify_risk(pct, critical_pct, warning_pct)
                inc_cli = (
                    build_quota_increase_cli("PROJECT", project_id, "compute.googleapis.com", qid, rname, limit)
                    if pct >= warning_pct
                    else ""
                )
                items.append(
                    QuotaMetricItem(
                        scope_type="PROJECT",
                        scope_id=project_id,
                        service="compute.googleapis.com",
                        quota_id=qid,
                        metric=f"compute.googleapis.com/{metric_code.lower()}",
                        display_name=f"Compute ({rname}) · {metric_code}",
                        region=rname,
                        usage=usage,
                        limit=limit,
                        utilization_pct=pct,
                        risk_level=risk,
                        recommendation=build_quota_recommendation(
                            "PROJECT", project_id, "compute.googleapis.com", qid, rname, pct, limit
                        ),
                        quota_increase_cli=inc_cli,
                    )
                )
    except Exception as exc:
        logger.debug("Compute regional quota scan skipped on %s: %s", project_id, type(exc).__name__)

    return items


def scan_serviceruntime_quotas_live(
    project_id: str,
    token: str,
    critical_pct: float = 90.0,
    warning_pct: float = 80.0,
) -> list[QuotaMetricItem]:
    """Query Cloud Monitoring `serviceruntime.googleapis.com/quota/*` allocation & rate usage vs limit."""
    now = datetime.datetime.now(datetime.UTC)
    start_alloc = (now - datetime.timedelta(hours=36)).strftime("%Y-%m-%dT%H:%M:%SZ")
    start_rate = (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _fetch_ts(metric_type: str, start_iso: str) -> list[dict[str, Any]]:
        flt = f'metric.type="{metric_type}"'
        params = urllib.parse.urlencode(
            {
                "filter": flt,
                "interval.startTime": start_iso,
                "interval.endTime": end_iso,
                "pageSize": 500,
            }
        )
        url = f"https://monitoring.googleapis.com/v3/projects/{urllib.parse.quote(project_id)}/timeSeries?{params}"
        try:
            return list(_gcp_get_json(url, token, timeout=25).get("timeSeries") or [])
        except Exception as exc:
            logger.debug("Monitoring %s skipped on %s: %s", metric_type, project_id, type(exc).__name__)
            return []

    def _point_val(pt: dict[str, Any]) -> float:
        val = pt.get("value") or {}
        for k in ("int64Value", "doubleValue"):
            if k in val:
                try:
                    return float(val[k])
                except (ValueError, TypeError):
                    return 0.0
        return 0.0

    # Key: (service, quota_metric, location, limit_name)
    limits_map: dict[tuple[str, str, str, str], float] = {}
    for ts in _fetch_ts("serviceruntime.googleapis.com/quota/limit", start_alloc):
        m_labels = (ts.get("metric") or {}).get("labels") or {}
        r_labels = (ts.get("resource") or {}).get("labels") or {}
        q_metric = str(m_labels.get("quota_metric") or "")
        lim_name = str(m_labels.get("limit_name") or "")
        svc = str(r_labels.get("service") or q_metric.split("/")[0] or "gcp")
        loc = str(r_labels.get("location") or "global")
        pts = ts.get("points") or []
        if not pts or not q_metric:
            continue
        lim_val = _point_val(pts[0])
        if lim_val > 0:
            limits_map[(svc, q_metric, loc, lim_name)] = lim_val
            limits_map.setdefault((svc, q_metric, loc, ""), lim_val)

    usage_map: dict[tuple[str, str, str], float] = {}
    for mtype, st_iso in (
        ("serviceruntime.googleapis.com/quota/allocation/usage", start_alloc),
        ("serviceruntime.googleapis.com/quota/rate/net_usage", start_rate),
    ):
        for ts in _fetch_ts(mtype, st_iso):
            m_labels = (ts.get("metric") or {}).get("labels") or {}
            r_labels = (ts.get("resource") or {}).get("labels") or {}
            q_metric = str(m_labels.get("quota_metric") or "")
            svc = str(r_labels.get("service") or q_metric.split("/")[0] or "gcp")
            loc = str(r_labels.get("location") or "global")
            pts = ts.get("points") or []
            if not pts or not q_metric:
                continue
            # Use peak recent point for rate/allocation safety
            peak_val = max((_point_val(p) for p in pts[:20]), default=0.0)
            if peak_val > 0:
                key = (svc, q_metric, loc)
                usage_map[key] = max(usage_map.get(key, 0.0), peak_val)

    results: list[QuotaMetricItem] = []
    for (svc, q_metric, loc), usage in usage_map.items():
        # Match exact location limit or global fallback limit
        limit = limits_map.get((svc, q_metric, loc, "")) or limits_map.get(
            (svc, q_metric, "global", "")
        )
        if not limit or limit <= 0:
            continue
        # Skip duplicate compute.googleapis.com metrics already reported accurately by Compute API
        if svc == "compute.googleapis.com":
            continue
        pct = round((usage / limit) * 100.0, 2)
        short_id = q_metric.split("/")[-1]
        risk = classify_risk(pct, critical_pct, warning_pct)
        results.append(
            QuotaMetricItem(
                scope_type="PROJECT",
                scope_id=project_id,
                service=svc,
                quota_id=short_id,
                metric=q_metric,
                display_name=f"{svc} ({loc}) · {short_id}",
                region=loc,
                usage=usage,
                limit=limit,
                utilization_pct=pct,
                risk_level=risk,
                recommendation=build_quota_recommendation(
                    "PROJECT", project_id, svc, short_id, loc, pct
                ),
            )
        )
    return results


def scan_quota_exceeded_events_live(project_id: str, token: str, days: int = 7) -> list[QuotaExceededEvent]:
    """Query Cloud Monitoring `serviceruntime.googleapis.com/quota/exceeded` over the past N days."""
    now = datetime.datetime.now(datetime.UTC)
    start_iso = (now - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    params = urllib.parse.urlencode(
        {
            "filter": 'metric.type="serviceruntime.googleapis.com/quota/exceeded"',
            "interval.startTime": start_iso,
            "interval.endTime": end_iso,
            "pageSize": 200,
        }
    )
    url = f"https://monitoring.googleapis.com/v3/projects/{urllib.parse.quote(project_id)}/timeSeries?{params}"
    try:
        series = list(_gcp_get_json(url, token, timeout=15).get("timeSeries") or [])
    except Exception as exc:
        logger.debug("quota/exceeded query skipped on %s: %s", project_id, type(exc).__name__)
        return []

    events: list[QuotaExceededEvent] = []
    for ts in series:
        m_labels = (ts.get("metric") or {}).get("labels") or {}
        r_labels = (ts.get("resource") or {}).get("labels") or {}
        q_metric = str(m_labels.get("quota_metric") or "")
        svc = str(r_labels.get("service") or q_metric.split("/")[0] or "gcp")
        loc = str(r_labels.get("location") or "global")
        pts = ts.get("points") or []
        total_cnt = 0
        latest_ts = ""
        for pt in pts:
            v = pt.get("value") or {}
            cnt = int(v.get("int64Value") or v.get("doubleValue") or 0)
            if cnt > 0:
                total_cnt += cnt
                end_t = str((pt.get("interval") or {}).get("endTime") or "")
                if end_t > latest_ts:
                    latest_ts = end_t
        if total_cnt > 0 and q_metric:
            events.append(
                QuotaExceededEvent(
                    project_id=project_id,
                    service=svc,
                    quota_metric=q_metric,
                    location=loc,
                    exceeded_count_7d=total_cnt,
                    latest_exceeded_at=latest_ts,
                )
            )
    events.sort(key=lambda e: e.exceeded_count_7d, reverse=True)
    return events


def scan_organization_quotas_live(
    org_id: str,
    token: str,
    critical_pct: float = 90.0,
    warning_pct: float = 80.0,
) -> tuple[list[QuotaMetricItem], list[OrgQuotaPreference], list[dict[str, str]]]:
    """Query Google Cloud Quotas API v1 at `organizations/{org_id}` level."""
    org_items: list[QuotaMetricItem] = []
    org_prefs: list[OrgQuotaPreference] = []
    diagnostics: list[dict[str, str]] = []

    if not org_id:
        return org_items, org_prefs, diagnostics

    clean_org = config.validate_org_id(org_id)
    pref_url = (
        f"https://cloudquotas.googleapis.com/v1/organizations/{clean_org}"
        "/locations/global/quotaPreferences?pageSize=100"
    )
    try:
        pref_data = _gcp_get_json(pref_url, token, timeout=20)
        for p in pref_data.get("quotaPreferences") or []:
            q_cfg = p.get("quotaConfig") or {}
            pref_val = float(q_cfg.get("preferredValue") or 0.0)
            granted_raw = q_cfg.get("grantedValue")
            granted_val = float(granted_raw) if granted_raw is not None else None
            org_prefs.append(
                OrgQuotaPreference(
                    name=str(p.get("name") or ""),
                    scope_type="ORGANIZATION",
                    scope_id=clean_org,
                    service=str(p.get("service") or ""),
                    quota_id=str(p.get("quotaId") or ""),
                    preferred_value=pref_val,
                    granted_value=granted_val,
                    reconciling=bool(p.get("reconciling", False)),
                    dimensions=dict(p.get("dimensions") or {}),
                )
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            diagnostics.append(
                {
                    "scope": f"organizations/{clean_org}",
                    "status": "PERMISSION_DENIED",
                    "message": (
                        f"组织级 Cloud Quotas API (`organizations/{clean_org}`) 当前缺少 `cloudquotas.quotas.get` 权限；"
                        "已完成项目级配额扫描与组织跨项目汇总。如需拉取组织容器级原生配额，请在组织层授予运行账号 `roles/cloudquotas.viewer`："
                        f"`gcloud organizations add-iam-policy-binding {clean_org} --member=serviceAccount:<RUNTIME_SA> --role=roles/cloudquotas.viewer`"
                    ),
                }
            )
            return org_items, org_prefs, diagnostics
        diagnostics.append(
            {
                "scope": f"organizations/{clean_org}",
                "status": f"HTTP_{exc.code}",
                "message": f"查询组织级 quotaPreferences 返回 HTTP {exc.code}",
            }
        )
        return org_items, org_prefs, diagnostics
    except Exception as exc:
        diagnostics.append(
            {
                "scope": f"organizations/{clean_org}",
                "status": type(exc).__name__,
                "message": f"组织级配额查询异常: {type(exc).__name__}",
            }
        )
        return org_items, org_prefs, diagnostics

    # If org-level Cloud Quotas permission IS granted, also inspect org-container quotaInfos
    for svc in ORG_QUOTA_SERVICES:
        info_url = (
            f"https://cloudquotas.googleapis.com/v1/organizations/{clean_org}"
            f"/locations/global/services/{svc}/quotaInfos?pageSize=50"
        )
        try:
            info_data = _gcp_get_json(info_url, token, timeout=15)
            for qi in info_data.get("quotaInfos") or []:
                for d_info in qi.get("dimensionsInfos") or []:
                    details = d_info.get("details") or {}
                    val = float(details.get("value") or 0.0)
                    if val <= 0:
                        continue
                    qid = str(qi.get("quotaId") or "ORG_QUOTA")
                    org_items.append(
                        QuotaMetricItem(
                            scope_type="ORGANIZATION",
                            scope_id=clean_org,
                            service=svc,
                            quota_id=qid,
                            metric=str(qi.get("metric") or qid),
                            display_name=str(qi.get("quotaDisplayName") or qid),
                            region="global",
                            usage=0.0,
                            limit=val,
                            utilization_pct=0.0,
                            risk_level=QuotaRiskLevel.HEALTHY,
                            recommendation="组织容器级配额上限已纳管",
                        )
                    )
        except Exception:
            continue

    return org_items, org_prefs, diagnostics


def get_mock_quota_fixture(
    org_id: str,
    projects: list[str],
    critical_pct: float = 90.0,
    warning_pct: float = 80.0,
) -> tuple[list[QuotaMetricItem], list[QuotaMetricItem], list[OrgQuotaPreference]]:
    """Deterministic realistic Project + Org quota dataset for MOCK testing."""
    p1 = projects[0] if projects else "demo-core-prod"
    p2 = projects[1] if len(projects) > 1 else "demo-edge-svc"
    raw_project_metrics = [
        ("PROJECT", p1, "aiplatform.googleapis.com", "OnlinePredictionRequestsPerMinutePerProjectPerBaseModel", "aiplatform.googleapis.com/online_prediction_requests", "Vertex AI Gemini Online Prediction RPM", "global", 2880.0, 3000.0),
        ("PROJECT", p1, "compute.googleapis.com", "NVIDIA_L4_GPUS-per-region", "compute.googleapis.com/nvidia_l4_gpus", "Compute (us-central1) · NVIDIA_L4_GPUS", "us-central1", 15.0, 16.0),
        ("PROJECT", p1, "compute.googleapis.com", "PSC_ILB_CONSUMER_FORWARDING_RULES_PER_PRODUCER_NETWORK", "compute.googleapis.com/psc_forwarding_rules", "Compute Global · PSC Forwarding Rules", "global", 86.0, 100.0),
        ("PROJECT", p2, "compute.googleapis.com", "CPUS-per-region", "compute.googleapis.com/cpus", "Compute (asia-east1) · CPUS", "asia-east1", 228.0, 240.0),
        ("PROJECT", p2, "run.googleapis.com", "MaxInstanceCountPerProjectRegion", "run.googleapis.com/max_instances", "Cloud Run (asia-east1) · Max Instances", "asia-east1", 420.0, 1000.0),
    ]
    proj_items: list[QuotaMetricItem] = []
    for scope_t, sid, svc, qid, mname, disp, reg, usg, lim in raw_project_metrics:
        pct = round((usg / lim) * 100.0, 2)
        proj_items.append(
            QuotaMetricItem(
                scope_type=scope_t,
                scope_id=sid,
                service=svc,
                quota_id=qid,
                metric=mname,
                display_name=disp,
                region=reg,
                usage=usg,
                limit=lim,
                utilization_pct=pct,
                risk_level=classify_risk(pct, critical_pct, warning_pct),
                recommendation=build_quota_recommendation(scope_t, sid, svc, qid, reg, pct),
            )
        )

    org_pct = round((47.0 / 50.0) * 100.0, 2)
    org_items = [
        QuotaMetricItem(
            scope_type="ORGANIZATION",
            scope_id=org_id or "123456789012",
            service="accesscontextmanager.googleapis.com",
            quota_id="ServicePerimetersPerOrganization",
            metric="accesscontextmanager.googleapis.com/service_perimeters",
            display_name="VPC Service Controls · Perimeters per Organization",
            region="global",
            usage=47.0,
            limit=50.0,
            utilization_pct=org_pct,
            risk_level=classify_risk(org_pct, critical_pct, warning_pct),
            recommendation=build_quota_recommendation(
                "ORGANIZATION",
                org_id or "123456789012",
                "accesscontextmanager.googleapis.com",
                "ServicePerimetersPerOrganization",
                "global",
                org_pct,
            ),
        )
    ]
    org_prefs = [
        OrgQuotaPreference(
            name=f"organizations/{org_id or '123456789012'}/locations/global/quotaPreferences/vpc-sc-pref",
            scope_type="ORGANIZATION",
            scope_id=org_id or "123456789012",
            service="accesscontextmanager.googleapis.com",
            quota_id="ServicePerimetersPerOrganization",
            preferred_value=100.0,
            granted_value=50.0,
            reconciling=True,
        )
    ]
    return proj_items, org_items, org_prefs
