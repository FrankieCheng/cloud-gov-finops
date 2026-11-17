# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""SQLite-backed MSA Cloud Governance ledger and Feishu interactive card renderer."""

from __future__ import annotations

import csv
import datetime
import io
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from bot import config
from bot.state_sync import load_state_snapshot_from_gcs, save_state_snapshot
from msa.models import MSACategory, MSARecord, MSAStatus, MSAUrgency
from msa.parser import (
    DEFAULT_SEED_MSA_ROWS,
    compute_deadline_and_urgency,
    detect_product_and_category,
    extract_milestone_dates,
    is_corrupted_next_field,
    make_msa_id,
    normalize_date_str,
    parse_tabular_msa_content,
    synthesize_remediation_steps,
)

URGENCY_LABELS_ZH = {
    MSAUrgency.OVERDUE_REVIEW: "🔴 已过节点待核查闭环",
    MSAUrgency.URGENT_7D: "🔴 7天内紧急截止",
    MSAUrgency.UPCOMING_30D: "🟠 30天内临期预警",
    MSAUrgency.UPCOMING_90D: "🟡 90天内需排期改造",
    MSAUrgency.PLANNED: "🔵 远期规划跟踪",
    MSAUrgency.INFO_ONLY: "⚪ 仅通知无需操作",
    MSAUrgency.RESOLVED: "✅ 已完成闭环/不涉及",
}


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class MSAGovernanceService:
    """Manages Mandatory Service Announcements, milestone countdowns, and mitigation tracking."""

    def __init__(self, db_path: Path | None = None, seed_default: bool = True) -> None:
        config.ensure_data_dir()
        self.db_path = db_path or config.DB_PATH
        self._init_db()
        if seed_default:
            self._seed_if_empty()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS msa_records (
                    msa_id TEXT PRIMARY KEY,
                    sent_date TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    category TEXT NOT NULL,
                    product_service TEXT NOT NULL,
                    action_required INTEGER NOT NULL DEFAULT 1,
                    what_summary TEXT NOT NULL,
                    when_timeline TEXT NOT NULL,
                    next_steps TEXT NOT NULL,
                    healed_from_error INTEGER NOT NULL DEFAULT 0,
                    milestones_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    owner TEXT NOT NULL DEFAULT '',
                    impacted_projects_json TEXT NOT NULL DEFAULT '[]',
                    notes TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS msa_audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    msa_id TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'system',
                    old_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    owner TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_snoozes (
                    finding_key TEXT PRIMARY KEY,
                    reason TEXT NOT NULL DEFAULT '',
                    actor TEXT NOT NULL DEFAULT 'admin',
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _seed_if_empty(self) -> None:
        with self._get_conn() as conn:
            cnt = conn.execute("SELECT COUNT(*) AS c FROM msa_records").fetchone()["c"]
        if cnt > 0:
            return
        seed_tsv = os.getenv("MSA_SEED_TSV_PATH", "").strip()
        if seed_tsv and Path(seed_tsv).is_file():
            self.import_from_tsv_file(Path(seed_tsv))
        else:
            self.ingest_rows(DEFAULT_SEED_MSA_ROWS)
        self._restore_remote_overrides_if_available()

    def _restore_remote_overrides_if_available(self) -> None:
        snap = load_state_snapshot_from_gcs()
        if not snap or not isinstance(snap, dict):
            return
        with self._get_conn() as conn:
            for m in snap.get("msa_overrides") or []:
                conn.execute(
                    """
                    UPDATE msa_records
                    SET status = ?, owner = ?, impacted_projects_json = ?, notes = ?, updated_at = ?
                    WHERE msa_id = ?
                    """,
                    (
                        m.get("status", "OPEN"),
                        m.get("owner", ""),
                        json.dumps(m.get("impacted_projects") or []),
                        m.get("notes", ""),
                        m.get("updated_at") or _utc_now_iso(),
                        m.get("msa_id", ""),
                    ),
                )
            for s in snap.get("alert_snoozes") or []:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO alert_snoozes (finding_key, reason, actor, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        s.get("finding_key", ""),
                        s.get("reason", ""),
                        s.get("actor", "admin"),
                        s.get("expires_at", ""),
                        s.get("created_at") or _utc_now_iso(),
                    ),
                )
            conn.commit()

    def _sync_snapshot(self) -> None:
        if config.get_api_mode() == "MOCK":
            return
        with self._get_conn() as conn:
            m_rows = conn.execute(
                "SELECT msa_id, status, owner, impacted_projects_json, notes, updated_at FROM msa_records"
            ).fetchall()
            s_rows = conn.execute("SELECT * FROM alert_snoozes").fetchall()
        payload = {
            "synced_at": _utc_now_iso(),
            "msa_overrides": [
                {
                    "msa_id": r["msa_id"],
                    "status": r["status"],
                    "owner": r["owner"],
                    "impacted_projects": json.loads(r["impacted_projects_json"] or "[]"),
                    "notes": r["notes"],
                    "updated_at": r["updated_at"],
                }
                for r in m_rows
            ],
            "alert_snoozes": [dict(r) for r in s_rows],
        }
        save_state_snapshot(payload, local_path=self.db_path.parent / "governance_state_snapshot.json")

    def ingest_rows(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Idempotently ingest/upsert MSA rows while preserving human governance status & owners."""
        inserted = 0
        updated = 0
        healed = 0
        now = _utc_now_iso()

        with self._get_conn() as conn:
            for raw in rows:
                sent_raw = str(raw.get("MSA Sent Date") or raw.get("sent_date") or "").strip()
                sent_iso = normalize_date_str(sent_raw) or _utc_now_iso()[:10]
                subj = str(raw.get("Email Subject") or raw.get("subject") or "").strip()
                what = str(raw.get("What") or raw.get("what_summary") or "").strip()
                when = str(raw.get("When") or raw.get("when_timeline") or "").strip()
                nxt = str(raw.get("Next") or raw.get("next_steps") or "").strip()
                prio = str(raw.get("Priority") or raw.get("priority") or "P3").strip().upper()
                if prio not in ("P1", "P2", "P3", "P4"):
                    prio = "P3"
                if not subj and not what:
                    continue

                msa_id = make_msa_id(sent_iso, subj)
                product, category, action_req = detect_product_and_category(subj, what)
                was_healed = 0
                if is_corrupted_next_field(nxt):
                    nxt = synthesize_remediation_steps(subj, what, when)
                    was_healed = 1
                    healed += 1

                milestones = extract_milestone_dates(f"{when}\n{what}")
                default_status = MSAStatus.NOT_APPLICABLE.value if not action_req else MSAStatus.OPEN.value

                existing = conn.execute(
                    "SELECT msa_id FROM msa_records WHERE msa_id = ?", (msa_id,)
                ).fetchone()
                if existing:
                    conn.execute(
                        """
                        UPDATE msa_records
                        SET priority = ?, category = ?, product_service = ?, action_required = ?,
                            what_summary = ?, when_timeline = ?, next_steps = ?,
                            healed_from_error = ?, milestones_json = ?, updated_at = ?
                        WHERE msa_id = ?
                        """,
                        (
                            prio,
                            category.value,
                            product,
                            1 if action_req else 0,
                            what,
                            when,
                            nxt,
                            was_healed,
                            json.dumps(milestones),
                            now,
                            msa_id,
                        ),
                    )
                    updated += 1
                else:
                    conn.execute(
                        """
                        INSERT INTO msa_records (
                            msa_id, sent_date, priority, subject, category, product_service,
                            action_required, what_summary, when_timeline, next_steps,
                            healed_from_error, milestones_json, status, owner,
                            impacted_projects_json, notes, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '[]', '', ?)
                        """,
                        (
                            msa_id,
                            sent_iso,
                            prio,
                            subj,
                            category.value,
                            product,
                            1 if action_req else 0,
                            what,
                            when,
                            nxt,
                            was_healed,
                            json.dumps(milestones),
                            default_status,
                            now,
                        ),
                    )
                    inserted += 1
            conn.commit()

        return {"inserted": inserted, "updated": updated, "healed_429_rows": healed}

    def import_from_tsv_file(self, file_path: Path) -> dict[str, Any]:
        content = file_path.read_text(encoding="utf-8")
        rows = parse_tabular_msa_content(content)
        return self.ingest_rows(rows)

    def import_from_text(self, tabular_text: str) -> dict[str, Any]:
        rows = parse_tabular_msa_content(tabular_text)
        return self.ingest_rows(rows)

    def add_single_msa(
        self,
        subject: str,
        what_summary: str,
        when_timeline: str,
        next_steps: str = "",
        priority: str = "P2",
        sent_date: str = "",
        impacted_projects: list[str] | None = None,
    ) -> MSARecord:
        sent = normalize_date_str(sent_date) or _utc_now_iso()[:10]
        self.ingest_rows(
            [
                {
                    "sent_date": sent,
                    "priority": priority,
                    "subject": subject,
                    "what_summary": what_summary,
                    "when_timeline": when_timeline,
                    "next_steps": next_steps,
                }
            ]
        )
        msa_id = make_msa_id(sent, subject)
        if impacted_projects:
            return self.update_msa_status(msa_id, impacted_projects=impacted_projects)
        return self.get_msa(msa_id)

    def _hydrate_row(
        self, row: sqlite3.Row, reference_date: datetime.date | None = None
    ) -> MSARecord:
        milestones: list[str] = json.loads(row["milestones_json"] or "[]")
        projects: list[str] = json.loads(row["impacted_projects_json"] or "[]")
        status_enum = MSAStatus(row["status"])
        action_req = bool(row["action_required"])
        primary_ddl, next_ddl, days_left, urgency = compute_deadline_and_urgency(
            milestones=milestones,
            sent_date_iso=row["sent_date"],
            action_required=action_req,
            status=status_enum,
            reference_date=reference_date,
        )
        return MSARecord(
            msa_id=row["msa_id"],
            sent_date=row["sent_date"],
            priority=row["priority"],
            subject=row["subject"],
            category=MSACategory(row["category"]),
            product_service=row["product_service"],
            action_required=action_req,
            what_summary=row["what_summary"],
            when_timeline=row["when_timeline"],
            next_steps=row["next_steps"],
            healed_from_error=bool(row["healed_from_error"]),
            milestones=milestones,
            primary_deadline=primary_ddl,
            next_upcoming_deadline=next_ddl,
            days_to_deadline=days_left,
            urgency=urgency,
            status=status_enum,
            owner=row["owner"] or "",
            impacted_projects=projects,
            notes=row["notes"] or "",
            updated_at=row["updated_at"],
        )

    def get_msa(
        self, msa_id_or_keyword: str, reference_date: datetime.date | None = None
    ) -> MSARecord:
        key = (msa_id_or_keyword or "").strip()
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM msa_records WHERE msa_id = ?", (key,)).fetchone()
            if not row:
                rows = conn.execute("SELECT * FROM msa_records ORDER BY sent_date DESC").fetchall()
                low = key.lower()
                for cand in rows:
                    if (
                        low in cand["msa_id"].lower()
                        or low in cand["subject"].lower()
                        or low in cand["product_service"].lower()
                    ):
                        row = cand
                        break
        if not row:
            raise KeyError(f"MSA '{key}' not found.")
        return self._hydrate_row(row, reference_date=reference_date)

    def list_msas(
        self,
        status_filter: str = "ALL",
        query: str = "",
        reference_date: datetime.date | None = None,
    ) -> list[MSARecord]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM msa_records ORDER BY sent_date DESC").fetchall()

        records = [self._hydrate_row(r, reference_date=reference_date) for r in rows]
        sf = (status_filter or "ALL").strip().upper()
        if sf == "ACTIVE":
            records = [
                r
                for r in records
                if r.status in (MSAStatus.OPEN, MSAStatus.IN_PROGRESS) and r.action_required
            ]
        elif sf in MSAStatus.__members__:
            records = [r for r in records if r.status.value == sf]

        q_clean = (query or "").strip().lower()
        if q_clean:
            records = [
                r
                for r in records
                if q_clean in r.subject.lower()
                or q_clean in r.what_summary.lower()
                or q_clean in r.product_service.lower()
                or q_clean in r.category.value.lower()
                or any(q_clean in p.lower() for p in r.impacted_projects)
            ]

        urgency_rank = {
            MSAUrgency.URGENT_7D: 0,
            MSAUrgency.OVERDUE_REVIEW: 1,
            MSAUrgency.UPCOMING_30D: 2,
            MSAUrgency.UPCOMING_90D: 3,
            MSAUrgency.PLANNED: 4,
            MSAUrgency.INFO_ONLY: 5,
            MSAUrgency.RESOLVED: 6,
        }
        records.sort(
            key=lambda r: (
                urgency_rank.get(r.urgency, 9),
                r.days_to_deadline if r.days_to_deadline is not None else 9999,
                r.priority,
            )
        )
        return records

    def update_msa_status(
        self,
        msa_id_or_keyword: str,
        status: str | None = None,
        owner: str | None = None,
        impacted_projects: list[str] | str | None = None,
        notes: str | None = None,
        actor: str = "admin",
    ) -> MSARecord:
        rec = self.get_msa(msa_id_or_keyword)
        old_status = rec.status.value
        new_status = old_status
        if status and status.strip():
            cand = status.strip().upper()
            if cand not in MSAStatus.__members__:
                raise ValueError(
                    f"Invalid MSA status '{status}'. Must be one of {list(MSAStatus.__members__)}."
                )
            new_status = cand

        new_owner = owner.strip() if owner is not None else rec.owner
        new_notes = notes.strip() if notes is not None else rec.notes
        if impacted_projects is None:
            proj_list = rec.impacted_projects
        elif isinstance(impacted_projects, str):
            proj_list = [p.strip() for p in impacted_projects.split(",") if p.strip()]
        else:
            proj_list = [str(p).strip() for p in impacted_projects if str(p).strip()]

        now = _utc_now_iso()
        with self._get_conn() as conn:
            conn.execute(
                """
                UPDATE msa_records
                SET status = ?, owner = ?, impacted_projects_json = ?, notes = ?, updated_at = ?
                WHERE msa_id = ?
                """,
                (new_status, new_owner, json.dumps(proj_list), new_notes, now, rec.msa_id),
            )
            if new_status != old_status or new_owner != rec.owner or new_notes != rec.notes:
                conn.execute(
                    """
                    INSERT INTO msa_audit_events (msa_id, actor, old_status, new_status, owner, notes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (rec.msa_id, actor or "admin", old_status, new_status, new_owner, new_notes, now),
                )
            conn.commit()
        self._sync_snapshot()
        return self.get_msa(rec.msa_id)

    def list_audit_events(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM msa_audit_events ORDER BY event_id DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [dict(r) for r in rows]

    def snooze_finding(
        self, finding_key: str, reason: str = "", days: int = 7, actor: str = "admin"
    ) -> dict[str, Any]:
        clean_key = (finding_key or "").strip()
        if not clean_key:
            raise ValueError("finding_key must not be empty.")
        eff_days = max(1, min(int(days), 90))
        now_dt = datetime.datetime.now(datetime.UTC)
        exp_iso = (now_dt + datetime.timedelta(days=eff_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alert_snoozes (finding_key, reason, actor, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (clean_key, reason.strip(), actor.strip() or "admin", exp_iso, now_iso),
            )
            conn.commit()
        self._sync_snapshot()
        return {
            "finding_key": clean_key,
            "reason": reason.strip(),
            "actor": actor.strip() or "admin",
            "expires_at": exp_iso,
            "days": eff_days,
        }

    def list_active_snoozes(self) -> list[dict[str, Any]]:
        now_iso = _utc_now_iso()
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM alert_snoozes WHERE expires_at > ? ORDER BY expires_at ASC",
                (now_iso,),
            ).fetchall()
        return [dict(r) for r in rows]

    def is_finding_snoozed(self, *candidate_keys: str) -> bool:
        active = {r["finding_key"].lower() for r in self.list_active_snoozes()}
        if not active:
            return False
        for ck in candidate_keys:
            low = (ck or "").strip().lower()
            if low and any(low == ak or ak in low for ak in active):
                return True
        return False

    def export_ledger_tsv(self) -> str:
        """Export healed, project-correlated MSA ledger back to clean TSV for Google Sheets."""
        records = self.list_msas(status_filter="ALL")
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter="\t", lineterminator="\n")
        writer.writerow(
            [
                "MSA ID",
                "MSA Sent Date",
                "Priority",
                "Governance Status",
                "Owner",
                "Impacted Projects",
                "Primary Deadline",
                "Product",
                "Email Subject",
                "What",
                "When",
                "Next (Healed)",
                "Notes",
            ]
        )
        for r in records:
            writer.writerow(
                [
                    r.msa_id,
                    r.sent_date,
                    r.priority,
                    r.status.value,
                    r.owner,
                    ",".join(r.impacted_projects),
                    r.next_upcoming_deadline or r.primary_deadline or "",
                    r.product_service,
                    r.subject,
                    r.what_summary,
                    r.when_timeline,
                    r.next_steps.replace("\n", " "),
                    r.notes,
                ]
            )
        return buf.getvalue()

    def auto_correlate_impacted_projects(self) -> dict[str, Any]:
        """Auto-detect and persist impacted GCP projects for each MSA based on live Billing Export usage."""
        from msa.impact_matcher import fetch_active_services_per_project, match_msa_to_projects

        svc_map = fetch_active_services_per_project()
        records = self.list_msas(status_filter="ALL")
        correlated_count = 0
        details: list[dict[str, Any]] = []

        for rec in records:
            auto_projs = match_msa_to_projects(rec, svc_map)
            merged = list(dict.fromkeys([*rec.impacted_projects, *auto_projs]))
            if merged != rec.impacted_projects:
                self.update_msa_status(rec.msa_id, impacted_projects=merged)
                correlated_count += 1
            if merged:
                details.append(
                    {
                        "msa_id": rec.msa_id,
                        "product_service": rec.product_service,
                        "priority": rec.priority,
                        "impacted_projects": merged,
                    }
                )

        return {
            "active_projects_profiled": sorted(svc_map.keys()),
            "msas_updated": correlated_count,
            "correlated_items": details,
        }

    def get_governance_radar(
        self, reference_date: datetime.date | None = None
    ) -> dict[str, Any]:
        all_items = self.list_msas(status_filter="ALL", reference_date=reference_date)
        active_items = [
            r
            for r in all_items
            if r.status in (MSAStatus.OPEN, MSAStatus.IN_PROGRESS) and r.action_required
        ]
        by_urgency: dict[str, list[dict[str, Any]]] = {}
        for r in active_items:
            by_urgency.setdefault(r.urgency.value, []).append(r.to_summary_dict())

        unowned_high_prio = sum(
            1 for r in active_items if r.priority in ("P1", "P2") and not (r.owner or "").strip()
        )
        return {
            "reference_date": (
                reference_date or datetime.datetime.now(datetime.UTC).date()
            ).isoformat(),
            "total_records": len(all_items),
            "active_actionable_count": len(active_items),
            "unowned_high_priority_count": unowned_high_prio,
            "healed_429_count": sum(1 for r in all_items if r.healed_from_error),
            "urgent_or_overdue_count": sum(
                1
                for r in active_items
                if r.urgency in (MSAUrgency.OVERDUE_REVIEW, MSAUrgency.URGENT_7D, MSAUrgency.UPCOMING_30D)
            ),
            "by_urgency": by_urgency,
            "items": [r.to_summary_dict() for r in all_items],
        }


def build_msa_feishu_card(
    radar: dict[str, Any], interactive_callbacks: bool = False
) -> dict[str, Any]:
    """Build a Feishu governance card (attaching clickable callback buttons when sent via App Bot)."""
    urgent_cnt = int(radar.get("urgent_or_overdue_count") or 0)
    active_cnt = int(radar.get("active_actionable_count") or 0)
    header_color = "red" if urgent_cnt > 0 else ("orange" if active_cnt > 0 else "green")

    overview = (
        f"巡检日期: {radar.get('reference_date')} | 总公告数: {radar.get('total_records', 0)} | "
        f"待闭环变更: {active_cnt} | 临期/待核查: {urgent_cnt} | "
        f"未指派责任人的 P1/P2 变更: {radar.get('unowned_high_priority_count', 0)}"
    )
    elements: list[dict[str, Any]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": overview}},
        {"tag": "hr"},
    ]

    items = [
        x
        for x in (radar.get("items") or [])
        if x.get("status") in ("OPEN", "IN_PROGRESS") and x.get("action_required")
    ]
    if not items:
        elements.append(
            {
                "tag": "div",
                "text": {"tag": "plain_text", "content": "✅ 当前无待处理的强制服务变更公告（MSA）。"},
            }
        )
    else:
        lines: list[str] = []
        for item in items[:8]:
            urg = MSAUrgency(item["urgency"])
            badge = URGENCY_LABELS_ZH.get(urg, urg.value)
            ddl = item.get("next_upcoming_deadline") or item.get("primary_deadline") or "详见正文"
            days = item.get("days_to_deadline")
            days_str = (
                f"（剩余 {days} 天）"
                if isinstance(days, int) and days >= 0
                else (f"（节点已过 {abs(days)} 天，请确认是否已处理）" if isinstance(days, int) else "")
            )
            first_next = (item.get("next_steps") or "").splitlines()[0][:140]
            projs = item.get("impacted_projects") or []
            proj_line = (
                f"\n受影响真实项目 ({len(projs)}): {', '.join(projs[:6])}"
                if projs
                else ""
            )
            owner_tag = f" | 责任人: {item.get('owner')}" if item.get("owner") else " | ⚠️待指派责任人"
            lines.append(
                f"{badge}\n"
                f"[{item.get('msa_id')}] [{item.get('priority')}] {item.get('product_service')} | 关键节点: {ddl}{days_str}{owner_tag}{proj_line}\n"
                f"主题: {str(item.get('subject') or '')[:120]}\n"
                f"建议动作: {first_next}"
            )
        elements.append(
            {"tag": "div", "text": {"tag": "plain_text", "content": "\n\n".join(lines)[:3800]}}
        )

        if interactive_callbacks:
            buttons: list[dict[str, Any]] = []
            for item in items[:3]:
                mid = str(item.get("msa_id") or "")
                prod_short = str(item.get("product_service") or "")[:12]
                if item.get("status") == "OPEN":
                    buttons.append(
                        {
                            "tag": "button",
                            "text": {"tag": "plain_text", "content": f"🔄 跟进 {prod_short} ({mid[-4:]})"},
                            "type": "default",
                            "value": {"gov_action": "msa_status", "msa_id": mid, "status": "IN_PROGRESS"},
                        }
                    )
                buttons.append(
                    {
                        "tag": "button",
                        "text": {"tag": "plain_text", "content": f"✅ 闭环 {prod_short} ({mid[-4:]})"},
                        "type": "primary",
                        "value": {"gov_action": "msa_status", "msa_id": mid, "status": "MITIGATED"},
                    }
                )
            if buttons:
                elements.append({"tag": "hr"})
                elements.append({"tag": "action", "actions": buttons[:6]})

    elements.append(
        {
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": "提示：支持直接点击按钮流转状态（机器人会话内）或发送「把 msa-xxxx 标记为 MITIGATED，责任人 张三」。",
                }
            ],
        }
    )
    cfg: dict[str, Any] = {"wide_screen_mode": True}
    if interactive_callbacks:
        cfg["update_multi"] = True
    return {
        "config": cfg,
        "header": {
            "template": header_color,
            "title": {
                "tag": "plain_text",
                "content": f"Google Cloud MSA 服务变更治理雷达（待处理 {active_cnt} 项）",
            },
        },
        "elements": elements,
    }


_msa_service_instance: MSAGovernanceService | None = None


def get_msa_service() -> MSAGovernanceService:
    global _msa_service_instance
    if _msa_service_instance is None:
        _msa_service_instance = MSAGovernanceService()
    return _msa_service_instance


def set_msa_service(svc: MSAGovernanceService | None) -> None:
    global _msa_service_instance
    _msa_service_instance = svc
