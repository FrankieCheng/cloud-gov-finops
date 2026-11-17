# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Parser, milestone date extractor, category classifier, and 429 dirty-data healer for MSA sheets & emails."""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import re
from typing import Any

from msa.models import MSACategory, MSAStatus, MSAUrgency

_DATE_PATTERN = re.compile(r"\b(20\d{2})[/-](0[1-9]|1[0-2])[/-](0[1-9]|[12]\d|3[01])\b")

# Representative synthetic MSA seed dataset (including a simulated 429 API error row for self-healing verification)
DEFAULT_SEED_MSA_ROWS: list[dict[str, str]] = [
    {
        "MSA Sent Date": "2026/09/15",
        "Priority": "P2",
        "Email Subject": "[GCP Service Announcement] [Action Required] Review legacy Gemini model retirement schedules on Vertex AI",
        "What": "Google Cloud is retiring legacy Gemini model versions on Vertex AI starting with public deprecation on 2026/10/20 and full discontinuation beginning 2027/01/28. Customers must migrate workloads to current generally available Gemini models before shutdown dates to prevent service disruptions.",
        "When": "- 2026/10/20: Public deprecation of legacy endpoints and blocking of new project usage - 2027/01/28: Discontinuation of legacy Flash-Lite endpoints - 2027/03/31: Discontinuation of legacy Flash and Pro endpoints across primary regions",
        "Next": "- Audit all projects calling legacy Gemini endpoints and migrate workloads to current GA Gemini models before 2027/01/28 and 2027/03/31.\n- Migrate any Provisioned Throughput orders via the self-service console.",
    },
    {
        "MSA Sent Date": "2026/09/14",
        "Priority": "P2",
        "Email Subject": "[GCP Service Announcement] [Action Required] Migrate Vertex AI legacy image generation endpoints before Mar 15, 2027",
        "What": "Google Cloud will permanently retire legacy image generation preview endpoints on 2027/03/15. To avoid service disruption, please migrate your image generation workflows to supported generally available Imagen / Gemini image models before this date.",
        "When": "- 2026/09/14: Legacy preview image endpoints marked deprecated. - 2027/03/15: Permanent retirement of legacy preview image endpoints.",
        "Next": "- Replace legacy preview image endpoint strings with current GA Imagen / Gemini image models before 2027/03/15.\n- Review updated billing rates and Provisioned Throughput configurations.",
    },
    {
        "MSA Sent Date": "2026/09/10",
        "Priority": "P4",
        "Email Subject": "[GCP Service Announcement] [Product Update] Rescheduling of quarterly maintenance window for Cloud SQL",
        "What": "Google Cloud announced on 2026/09/10 that the scheduled quarterly automated maintenance updates for Cloud SQL for PostgreSQL and MySQL instances have been postponed. No action is required to maintain uninterrupted service.",
        "When": "2026/09/10: Postponement of scheduled quarterly maintenance for Cloud SQL (PostgreSQL and MySQL)",
        "Next": "- No mandatory action required; apply minor upgrades manually via Self-Service Maintenance if desired.",
    },
    {
        "MSA Sent Date": "2026/09/09",
        "Priority": "P3",
        "Email Subject": "[GCP Service Announcement] [Action Advised] Google Cloud Backup and DR Service API automatic enablement",
        "What": "Starting 2026/10/21, Google Cloud will automatically enable the Backup and DR Service API on projects with active Compute Engine, Cloud SQL, AlloyDB, or Filestore APIs. To opt out of automatic enablement, submit the opt-out form by 2026/10/01.",
        "When": "- 2026/10/01: Deadline to submit opt-out form - 2026/10/21: Automatic enablement of Backup and DR Service API across active projects using Compute Engine, Cloud SQL, AlloyDB, or Filestore",
        "Next": 'Error: Gemini API call failed (429): { "error": { "code": 429, "message": "Resource exhausted.", "status": "RESOURCE_EXHAUSTED" } }',
    },
    {
        "MSA Sent Date": "2026/09/08",
        "Priority": "P3",
        "Email Subject": "[GCP Service Announcement] [Billing Update] Cloud Networking Internal passthrough Network LB metering update in Nov 2026",
        "What": "Starting 2026/11/01, Google Cloud will update network telemetry metering to accurately bill outbound data processed by Internal passthrough Network Load Balancers. There will be no service interruptions or retroactive charges.",
        "When": "2026/11/01: Metering update for outbound data processed by Internal passthrough Network Load Balancers.",
        "Next": "- Audit projects using next-hop Internal Passthrough Network Load Balancers via VPC Flow Logs and verify post-2026/11/01 network egress SKU charges in Billing Export.",
    },
    {
        "MSA Sent Date": "2026/08/31",
        "Priority": "P2",
        "Email Subject": "[GCP Service Announcement] [Action Required] Review configuration for upcoming Cloud DNS CNAME resolution changes",
        "What": "On 2027/01/05, Cloud DNS will update CNAME chasing to follow VPC name resolution order across public and private zones. Customers should review DNS configurations before this date to prevent unexpected routing.",
        "When": "2027/01/05: Cloud DNS updates CNAME chasing order across public and private zones.",
        "Next": "- Audit Cloud DNS private/public zones and response policies for cross-zone CNAME chasing before 2027/01/05.\n- Test resolution paths with dig/nslookup and align TTL values.",
    },
    {
        "MSA Sent Date": "2026/08/25",
        "Priority": "P3",
        "Email Subject": "[GCP Service Announcement] [Reminder] Firebase Remote Config usage-based pricing transition",
        "What": "Firebase Remote Config transitions to a usage-based pricing model starting 2026/09/01 with a free tier of 100,000 daily fetches. Following a grace period, billing above the free tier begins on 2027/02/01.",
        "When": "- 2026/09/01: Effective date for usage-based pricing model - 2027/02/01: Commencement of billing above daily free tier",
        "Next": "- Check daily Firebase Remote Config fetch volume per project against the 100,000/day free tier before 2027/02/01.",
    },
]


def normalize_date_str(raw: str) -> str:
    m = _DATE_PATTERN.search(raw or "")
    if not m:
        return (raw or "").strip()
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"


def extract_milestone_dates(text: str) -> list[str]:
    found: list[str] = []
    for m in _DATE_PATTERN.finditer(text or ""):
        iso = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        if iso not in found:
            found.append(iso)
    found.sort()
    return found


def make_msa_id(sent_date: str, subject: str) -> str:
    clean_subj = re.sub(r"^(re|fwd)\s*:\s*", "", (subject or "").strip(), flags=re.IGNORECASE)
    digest = hashlib.sha256(f"{normalize_date_str(sent_date)}|{clean_subj.lower()}".encode()).hexdigest()[:10]
    return f"msa-{digest}"


def detect_product_and_category(subject: str, what: str) -> tuple[str, MSACategory, bool]:
    combined = f"{subject}\n{what}".lower()
    product = "Google Cloud"
    for kw, label in (
        ("gemini", "Vertex AI / Gemini"),
        ("vertex", "Vertex AI / Gemini"),
        ("cloud sql", "Cloud SQL"),
        ("cloud dns", "Cloud DNS"),
        ("load balanc", "Cloud Load Balancing"),
        ("backup and dr", "Backup and DR"),
        ("firebase", "Firebase"),
        ("gke", "Google Kubernetes Engine"),
        ("kubernetes", "Google Kubernetes Engine"),
        ("bigquery", "BigQuery"),
        ("compute engine", "Compute Engine"),
    ):
        if kw in combined:
            product = label
            break

    no_action = (
        "no action is required" in combined
        or "[product update]" in combined
        and "cancellation" in combined
    )
    action_required = not no_action

    if any(k in combined for k in ("retir", "discontinu", "deprecat", "shutdown")):
        cat = MSACategory.RETIREMENT
    elif any(k in combined for k in ("[billing update]", "pricing", "billing discrepancy", "bill outbound")):
        cat = MSACategory.BILLING_CHANGE
    elif "automatic enablement" in combined or "opt-out" in combined or "opt out" in combined:
        cat = MSACategory.API_ENABLEMENT
    elif "maintenance" in combined:
        cat = MSACategory.MAINTENANCE
    elif "[action required]" in combined or "resolution changes" in combined or "breaking" in combined:
        cat = MSACategory.BREAKING_CHANGE
    else:
        cat = MSACategory.GENERAL

    return product, cat, action_required


def is_corrupted_next_field(next_text: str) -> bool:
    clean = (next_text or "").strip()
    if not clean:
        return True
    lower = clean.lower()
    return (
        "gemini api call failed" in lower
        or "resource_exhausted" in lower
        or ('"error"' in lower and '"code": 429' in lower)
    )


def synthesize_remediation_steps(subject: str, what: str, when: str) -> str:
    """Deterministically heal missing or 429-corrupted `Next` columns using grounded announcement facts."""
    milestones = extract_milestone_dates(f"{when}\n{what}")
    ddl_note = f"（关键时间节点：{', '.join(milestones)}）" if milestones else ""
    combined = f"{subject}\n{what}".lower()

    bullets: list[str] = []
    if "opt out" in combined or "opt-out" in combined or "automatic enablement" in combined:
        bullets.append(
            f"- 核查组织及各活跃 Project（Compute Engine / Cloud SQL / AlloyDB / Filestore）是否允许自动启用该 API {ddl_note}。"
        )
        bullets.append(
            "- 若安全合规或组织策略不需要自动启用，检查是否已提交 Opt-out 豁免表单，或在启用后通过 Organization Policy / Service Usage 审计权限与配额影响。"
        )
        bullets.append(
            "- 确认自动启用 API 本身是否产生额外计费，并在巡检台标记核查结论。"
        )
    elif "retir" in combined or "discontinu" in combined or "migrate" in combined:
        bullets.append(
            f"- 盘点所有调用旧版本模型/接口的 Project 与线上服务实例，制定迁移排期 {ddl_note}。"
        )
        bullets.append(
            "- 在测试环境切换至官方推荐的 GA 替代端点完成回归验证，并检查预留吞吐（Provisioned Throughput）或配额迁移。"
        )
    elif "billing" in combined or "pricing" in combined:
        bullets.append(
            f"- 结合 BigQuery Billing Export 评估受影响服务/SKU 的历史用量与预计账单增幅 {ddl_note}。"
        )
        bullets.append("- 生效首周在每日账单异常监控中重点关注对应项目的净成本变化。")
    else:
        bullets.append(f"- 对照公告内容排查受影响的 GCP Project 配置与依赖项 {ddl_note}。")
        bullets.append("- 完成验证或架构调整后在云管台将本条 MSA 更新为 MITIGATED（已闭环）。")

    return "\n".join(bullets)


def compute_deadline_and_urgency(
    milestones: list[str],
    sent_date_iso: str,
    action_required: bool,
    status: MSAStatus,
    reference_date: datetime.date | None = None,
) -> tuple[str, str, int | None, MSAUrgency]:
    """Compute `(primary_deadline, next_upcoming_deadline, days_to_deadline, urgency)`."""
    today = reference_date or datetime.datetime.now(datetime.UTC).date()
    if status in (MSAStatus.MITIGATED, MSAStatus.NOT_APPLICABLE):
        primary = milestones[-1] if milestones else ""
        return primary, "", None, MSAUrgency.RESOLVED

    if not action_required:
        primary = milestones[-1] if milestones else ""
        return primary, "", None, MSAUrgency.INFO_ONLY

    # Filter out milestone dates thatmerely repeat the announcement sent date when later dates exist
    effective = [d for d in milestones if d != sent_date_iso] or list(milestones)
    if not effective:
        return "", "", None, MSAUrgency.PLANNED

    parsed_dates: list[tuple[str, datetime.date]] = []
    for d_str in effective:
        try:
            parsed_dates.append((d_str, datetime.date.fromisoformat(d_str)))
        except ValueError:
            continue

    if not parsed_dates:
        return "", "", None, MSAUrgency.PLANNED

    future_or_today = [(s, d) for s, d in parsed_dates if d >= today]
    past_dates = [(s, d) for s, d in parsed_dates if d < today]

    primary_deadline = parsed_dates[-1][0]
    if future_or_today:
        next_str, next_dt = future_or_today[0]
        days_left = (next_dt - today).days
        if days_left <= 7:
            return primary_deadline, next_str, days_left, MSAUrgency.URGENT_7D
        if days_left <= 30:
            return primary_deadline, next_str, days_left, MSAUrgency.UPCOMING_30D
        if days_left <= 90:
            return primary_deadline, next_str, days_left, MSAUrgency.UPCOMING_90D
        return primary_deadline, next_str, days_left, MSAUrgency.PLANNED

    # All milestones are already in the past, while status is still OPEN/IN_PROGRESS!
    last_past_str, last_past_dt = past_dates[-1]
    days_overdue = (last_past_dt - today).days  # negative integer
    return primary_deadline, last_past_str, days_overdue, MSAUrgency.OVERDUE_REVIEW


def parse_tabular_msa_content(content: str, delimiter: str | None = None) -> list[dict[str, Any]]:
    """Parse TSV or CSV MSA sheet export into normalized dictionaries."""
    if not content or not content.strip():
        return []
    first_line = content.splitlines()[0]
    delim = delimiter or ("\t" if "\t" in first_line else ",")
    reader = csv.DictReader(io.StringIO(content), delimiter=delim)
    out: list[dict[str, Any]] = []
    for row in reader:
        if not row:
            continue
        sent = (row.get("MSA Sent Date") or row.get("sent_date") or "").strip()
        subj = (row.get("Email Subject") or row.get("subject") or "").strip()
        what = (row.get("What") or row.get("what_summary") or "").strip()
        when = (row.get("When") or row.get("when_timeline") or "").strip()
        nxt = (row.get("Next") or row.get("next_steps") or "").strip()
        prio = (row.get("Priority") or row.get("priority") or "P3").strip().upper()
        if not subj and not what:
            continue
        out.append(
            {
                "sent_date": sent,
                "priority": prio if prio in ("P1", "P2", "P3", "P4") else "P3",
                "subject": subj,
                "what_summary": what,
                "when_timeline": when,
                "next_steps": nxt,
            }
        )
    return out
