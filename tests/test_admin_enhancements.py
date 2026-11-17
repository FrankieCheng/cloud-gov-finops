# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Account Admin & FinOps Governance enhancements across msa/, quota/, billing/, and bot/."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from billing.finops_governance import compute_eom_forecast_and_budget
from billing.service import build_finops_governance_feishu_card, get_billing_service
from bot.agent import run_deterministic_gov_turn
from bot.feishu_bot import GovFeishuBot
from bot.scheduler import GovernancePatrolScheduler
from bot.server import app
from msa.service import MSAGovernanceService, build_msa_feishu_card, set_msa_service
from quota.hygiene import _extract_exposed_sensitive_ports, build_account_hygiene_feishu_card
from quota.scanner import build_quota_increase_cli
from quota.service import get_quota_service


class _SyncExec:
    def submit(self, fn, *args, **kwargs):  # type: ignore[no-untyped-def]
        return fn(*args, **kwargs)


def test_eom_forecast_esr_label_audit_idle_waste_and_arch_advisor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOV_API_MODE", "MOCK")
    fc = compute_eom_forecast_and_budget(
        as_of_date_iso="2026-11-15",
        mtd_net_cost=600.0,
        avg_7d_daily_net=50.0,
        monthly_budget_usd=1000.0,
    )
    assert fc["days_elapsed"] == 15
    assert fc["days_in_month"] == 30
    assert fc["eom_forecast_net_usd"] > 1000.0
    assert fc["budget_status"] == "EXCEEDED"

    svc = get_billing_service()
    rep = svc.generate_finops_governance_report(monthly_budget_usd=1000.0, as_of_date="2026-11-15")
    assert rep.effective_savings_rate_pct > 0
    assert rep.estimated_monthly_waste_usd == 41.30
    assert len(rep.idle_waste_items) == 2
    assert rep.unlabeled_spend_pct == 59.0
    card = build_finops_governance_feishu_card(rep)
    assert "FinOps" in card["header"]["title"]["content"]

    arch = svc.analyze_architecture()
    assert arch["estimated_monthly_arch_savings_usd"] > 100.0
    assert arch["architectural_recommendations"][0]["category"] == "INTRA_ORG_VPN_TO_PEERING"


def test_firewall_sensitive_port_filter_and_account_hygiene(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOV_API_MODE", "MOCK")
    # 80/443 web ingress must NOT trigger false-positive critical/high alerts
    all_p, sens = _extract_exposed_sensitive_ports([{"IPProtocol": "tcp", "ports": ["80", "443"]}])
    assert not all_p and sens == []

    # SSH + RDP range must be flagged
    all_p2, sens2 = _extract_exposed_sensitive_ports(
        [{"IPProtocol": "tcp", "ports": ["20-25", "3389"]}]
    )
    assert not all_p2 and "22/SSH" in sens2 and "3389/RDP" in sens2

    # IPProtocol: all must flag allows_all_protocols=True
    all_p3, _ = _extract_exposed_sensitive_ports([{"IPProtocol": "all"}])
    assert all_p3 is True

    cli = build_quota_increase_cli(
        "PROJECT", "demo-core-prod", "compute.googleapis.com", "CPUS-per-region", "us-central1", 24.0
    )
    assert "gcloud alpha quotas preferences create" in cli
    assert "--preferred-value=36" in cli

    q_rep = get_quota_service().scan_all()
    assert len(q_rep.recent_exceeded_events) == 1

    hyg = get_quota_service().audit_hygiene()
    assert hyg.keys_over_90_days == 1
    assert hyg.open_firewall_rules_count == 1
    card = build_account_hygiene_feishu_card(hyg)
    assert card["header"]["template"] == "red"


def test_msa_audit_log_snooze_tsv_export_and_feishu_card_callback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOV_API_MODE", "MOCK")
    monkeypatch.setenv("CHAT_ENGINE", "deterministic")
    msa_svc = MSAGovernanceService(db_path=tmp_path / "corr_msa.db", seed_default=True)
    set_msa_service(msa_svc)
    try:
        corr = msa_svc.auto_correlate_impacted_projects()
        assert corr["msas_updated"] >= 5
        gemini_msa = msa_svc.get_msa("legacy Gemini")
        assert "demo-core-prod" in gemini_msa.impacted_projects

        # Webhook card (interactive_callbacks=False) must NOT contain callback action tags
        webhook_card = build_msa_feishu_card(
            msa_svc.get_governance_radar(), interactive_callbacks=False
        )
        assert all(el.get("tag") != "action" for el in webhook_card["elements"])

        # App Bot card (interactive_callbacks=True) MUST contain clickable buttons
        bot_card = build_msa_feishu_card(
            msa_svc.get_governance_radar(), interactive_callbacks=True
        )
        assert any(el.get("tag") == "action" for el in bot_card["elements"])

        # Test one-click Feishu card button callback + audit trail + PATCH card
        fake_api = MagicMock()
        bot = GovFeishuBot(
            fake_api,
            lambda _u, _s, txt: run_deterministic_gov_turn(txt),
            executor=_SyncExec(),
            bot_open_id="ou_gov_bot",
            reply_classifier=lambda _h, _sp, txt: "账单" in txt,
        )
        cb_data = SimpleNamespace(
            event=SimpleNamespace(
                operator=SimpleNamespace(open_id="ou_admin_99"),
                action=SimpleNamespace(
                    value={
                        "gov_action": "msa_status",
                        "msa_id": gemini_msa.msa_id,
                        "status": "MITIGATED",
                    }
                ),
                context=SimpleNamespace(open_message_id="om_msa_card_1"),
            )
        )
        toast = bot.handle_card_action(cb_data)
        assert toast["toast"]["type"] == "success"
        fake_api.patch_card.assert_called_once()
        assert msa_svc.get_msa(gemini_msa.msa_id).status.value == "MITIGATED"
        audit_events = msa_svc.list_audit_events()
        assert len(audit_events) == 1
        assert audit_events[0]["new_status"] == "MITIGATED"

        # Test group chat reply_classifier ignoring unrelated human chatter
        bot._touch_conv("oc_grp_1", "ou_user_1")
        chatter_ev = SimpleNamespace(
            event=SimpleNamespace(
                sender=SimpleNamespace(
                    sender_id=SimpleNamespace(open_id="ou_user_1"), sender_type="user"
                ),
                message=SimpleNamespace(
                    message_id="om_chatter_1",
                    chat_id="oc_grp_1",
                    chat_type="group",
                    message_type="text",
                    content=json.dumps({"text": "中午去吃火锅吗？"}),
                    mentions=[],
                    parent_id="",
                ),
            )
        )
        bot.handle_message_event(chatter_ev)
        fake_api.reply_markdown.assert_not_called()

        # Test Alert Snooze suppressing muted finding cleanly
        msa_svc.snooze_finding("a1b2c3d4e5f6", reason="Scheduled weekend rotation", days=7)
        hyg_after = get_quota_service().audit_hygiene(force_refresh=True)
        assert hyg_after.keys_over_90_days == 0
        assert hyg_after.snoozed_findings_count == 1

        # Test TSV export & new FastAPI endpoints
        tsv_out = msa_svc.export_ledger_tsv()
        assert "MSA ID\tMSA Sent Date" in tsv_out
        assert gemini_msa.msa_id in tsv_out

        sched = GovernancePatrolScheduler()
        exec_patrol = sched.run_patrol(scope="EXECUTIVE", push_to_feishu=False)
        assert len(exec_patrol["cards"]) == 6

        client = TestClient(app)
        assert client.get("/api/billing/governance").status_code == 200
        assert client.get("/api/billing/architecture").status_code == 200
        assert client.get("/api/quota/hygiene").status_code == 200
        assert client.get("/api/executive/health").status_code == 200
        assert client.get("/api/msa/export.tsv").status_code == 200
        assert client.get("/api/msa/audit-log").status_code == 200

        csrf = client.get("/api/session").json()["csrf_token"]
        snz = client.post(
            "/api/alerts/snooze",
            json={"finding_key": "allow-internet-access-ingress", "reason": "ack", "days": 3},
            headers={"X-CSRF-Token": csrf},
        )
        assert snz.status_code == 200
    finally:
        set_msa_service(None)
