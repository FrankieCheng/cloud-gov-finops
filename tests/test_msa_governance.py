# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit & integration tests for the `msa/` Cloud Governance directory."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from msa.models import MSACategory, MSAStatus, MSAUrgency
from msa.service import MSAGovernanceService, build_msa_feishu_card


def test_msa_seed_heals_429_dirty_row_and_classifies_milestones(tmp_path: Path) -> None:
    svc = MSAGovernanceService(db_path=tmp_path / "msa.db", seed_default=True)
    radar = svc.get_governance_radar(reference_date=datetime.date(2026, 11, 16))
    assert radar["total_records"] == 7
    assert radar["healed_429_count"] == 1

    # Row 4 (Backup and DR API automatic enablement) had 429 error in source sheet -> healed!
    bdr = svc.get_msa("Backup and DR", reference_date=datetime.date(2026, 11, 16))
    assert bdr.healed_from_error is True
    assert "429" not in bdr.next_steps
    assert bdr.category == MSACategory.API_ENABLEMENT
    assert bdr.urgency == MSAUrgency.OVERDUE_REVIEW

    # Cloud SQL postponed maintenance requires no action -> INFO_ONLY / NOT_APPLICABLE
    sql_msa = svc.get_msa("Cloud SQL", reference_date=datetime.date(2026, 11, 16))
    assert sql_msa.action_required is False
    assert sql_msa.status == MSAStatus.NOT_APPLICABLE
    assert sql_msa.urgency == MSAUrgency.RESOLVED

    # Cloud DNS CNAME change on 2027-01-05 is 50 days from 2026-11-16 -> UPCOMING_90D
    dns_msa = svc.get_msa("Cloud DNS CNAME", reference_date=datetime.date(2026, 11, 16))
    assert dns_msa.category == MSACategory.BREAKING_CHANGE
    assert dns_msa.next_upcoming_deadline == "2027-01-05"
    assert dns_msa.days_to_deadline == 50
    assert dns_msa.urgency == MSAUrgency.UPCOMING_90D


def test_msa_status_lifecycle_and_idempotent_tsv_import(tmp_path: Path) -> None:
    svc = MSAGovernanceService(db_path=tmp_path / "msa2.db", seed_default=True)
    updated = svc.update_msa_status(
        "Cloud DNS CNAME",
        status="MITIGATED",
        owner="net-sre@example.com",
        impacted_projects="demo-core-prod,demo-shared-dns",
        notes="Audited all private/public DNS zones; no cross-zone CNAME chasing.",
    )
    assert updated.status == MSAStatus.MITIGATED
    assert updated.owner == "net-sre@example.com"
    assert updated.impacted_projects == ["demo-core-prod", "demo-shared-dns"]

    # Re-ingesting updated TSV keeps MITIGATED status & owner intact
    tsv = (
        "MSA Sent Date\tPriority\tEmail Subject\tWhat\tWhen\tNext\n"
        "2026/08/31\tP2\t[GCP Service Announcement] [Action Required] Review configuration for upcoming Cloud DNS CNAME resolution changes\tUpdated summary\t2027/01/05: Effective\tAudit DNS\n"
    )
    stats = svc.import_from_text(tsv)
    assert stats["updated"] == 1
    reloaded = svc.get_msa("Cloud DNS CNAME")
    assert reloaded.status == MSAStatus.MITIGATED
    assert reloaded.owner == "net-sre@example.com"

    card = build_msa_feishu_card(svc.get_governance_radar())
    assert card["header"]["template"] in ("red", "orange", "green")
    assert "Google Cloud MSA" in card["header"]["title"]["content"]
    json.dumps(card, ensure_ascii=False)
