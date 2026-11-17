# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit & integration tests for the `billing/` BigQuery Export FinOps module."""

from __future__ import annotations

import json

import pytest

from billing.analyzer import BILLING_ACCOUNT_BUCKET
from billing.service import BillingFinOpsService, build_billing_feishu_card
from bot import config


def test_mock_billing_daily_summary_and_top_n_anomalies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOV_API_MODE", "MOCK")
    svc = BillingFinOpsService(top_n=3, min_delta_usd=1.0, min_pct=20.0)
    rep = svc.generate_daily_report()

    # Must include project-level AND _BILLING_ACCOUNT_LEVEL_ (NULL project.id) buckets
    proj_ids = {p.project_id for p in rep.projects_summary}
    assert "demo-core-prod" in proj_ids
    assert BILLING_ACCOUNT_BUCKET in proj_ids

    # Top-N anomalies detected and ranked with SKU root-cause drivers
    assert len(rep.suspected_anomalies) == 3
    top1 = rep.suspected_anomalies[0]
    assert top1.project_id == "demo-core-prod"
    assert top1.severity == "CRITICAL"
    assert top1.top_sku_drivers[0].service == "Vertex AI"

    # Intraday runaway alert caught on demo-edge-svc ($19.40 today vs $6.85 yesterday)
    assert len(rep.intraday_alerts) == 1
    assert rep.intraday_alerts[0].project_id == "demo-edge-svc"

    card = build_billing_feishu_card(rep)
    assert card["header"]["template"] == "red"
    card_txt = json.dumps(card, ensure_ascii=False)
    assert "Gemini Online Prediction" in card_txt
    assert BILLING_ACCOUNT_BUCKET in card_txt


def test_sql_injection_table_identifier_blocked() -> None:
    for payload in (
        "demo-core-prod.billing.tbl` UNION ALL SELECT * FROM secrets--",
        "demo-core-prod.billing.tbl; DROP TABLE users",
        "../etc/passwd",
    ):
        with pytest.raises(ValueError):
            config.validate_bq_table_id(payload)

    for bad_date in ("2026-11-08' OR '1'='1", "2026/11/08", "tomorrow"):
        with pytest.raises(ValueError):
            config.validate_iso_date(bad_date)
