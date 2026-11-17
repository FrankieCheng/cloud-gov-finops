# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for GovFeishuBot, Patrol Scheduler, FastAPI CSRF/SSRF/Security Headers."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from bot import config
from bot.agent import run_deterministic_gov_turn
from bot.feishu_bot import GovFeishuBot
from bot.scheduler import (
    GovernancePatrolScheduler,
    compute_feishu_webhook_sign,
    send_feishu_webhook_card,
)
from bot.server import app
from msa.service import MSAGovernanceService, set_msa_service


class _SyncExec:
    def submit(self, fn: Any, *args: Any, **kwargs: Any) -> None:
        fn(*args, **kwargs)


def test_feishu_webhook_ssrf_guardrail(monkeypatch: pytest.MonkeyPatch) -> None:
    assert config.validate_feishu_webhook_url("https://open.feishu.cn/open-apis/bot/v2/hook/abc")
    for bad in (
        "http://open.feishu.cn/open-apis/bot/v2/hook/abc",
        "https://169.254.169.254/computeMetadata/v1/",
        "https://evil.example.com/open.feishu.cn",
    ):
        with pytest.raises(ValueError):
            config.validate_feishu_webhook_url(bad)

    # Verify Feishu v2 HMAC-SHA256 webhook signature format & non-zero code rejection
    sig = compute_feishu_webhook_sign("1700000000", "unit_test_secret")
    assert len(sig) == 44 and sig.endswith("=")

    class _FakeResp:
        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def read(self) -> bytes:
            return b'{"code": 19021, "msg": "sign match fail"}'

    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_kw: _FakeResp())
    with pytest.raises(RuntimeError, match="19021"):
        send_feishu_webhook_card(
            "https://open.feishu.cn/open-apis/bot/v2/hook/abc",
            {"header": {}, "elements": []},
            webhook_secret="unit_test_secret",
        )


def test_gov_feishu_bot_queries_and_tsv_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOV_API_MODE", "MOCK")
    msa_svc = MSAGovernanceService(db_path=tmp_path / "bot_msa.db", seed_default=True)
    set_msa_service(msa_svc)
    try:
        api = MagicMock()
        api.reply_markdown.return_value = "om_bot_md1"
        api.reply_card.return_value = "om_bot_card1"
        bot = GovFeishuBot(
            api,
            lambda _u, _s, txt: run_deterministic_gov_turn(txt),
            executor=_SyncExec(),
            bot_open_id="ou_gov_bot",
        )

        # 1. Ask for full governance patrol in group with @bot
        ev = SimpleNamespace(
            event=SimpleNamespace(
                sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="ou_finops_1"), sender_type="user"),
                message=SimpleNamespace(
                    message_id="om_1",
                    chat_id="oc_gov_group",
                    chat_type="group",
                    message_type="text",
                    content=json.dumps({"text": "@_user_1 执行全面巡检"}),
                    mentions=[
                        SimpleNamespace(
                            key="@_user_1",
                            id=SimpleNamespace(open_id="ou_gov_bot"),
                            mentioned_type="bot",
                        )
                    ],
                    parent_id="",
                ),
            )
        )
        bot.handle_message_event(ev)
        api.reply_markdown.assert_called_once()
        # Full patrol attaches 3 cards: MSA + QUOTA + BILLING
        assert api.reply_card.call_count == 3

        # 2. Upload TSV MSA export file in DM
        tsv_bytes = (
            b"MSA Sent Date\tPriority\tEmail Subject\tWhat\tWhen\tNext\n"
            b"2026/11/15\tP2\t[GCP Service Announcement] [Action Required] GKE 1.29 End of Support\t"
            b"Upgrade GKE clusters before 2026/12/01.\t2026/12/01: EoS\tUpgrade control plane and node pools.\n"
        )
        api.download_file_resource.return_value = tsv_bytes
        file_ev = SimpleNamespace(
            event=SimpleNamespace(
                sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="ou_finops_1"), sender_type="user"),
                message=SimpleNamespace(
                    message_id="om_2",
                    chat_id="oc_dm_1",
                    chat_type="p2p",
                    message_type="file",
                    content=json.dumps({"file_key": "file_v3_msa", "file_name": "msa_latest.tsv"}),
                    mentions=[],
                    parent_id="",
                ),
            )
        )
        bot.handle_message_event(file_ev)
        assert msa_svc.get_msa("GKE 1.29").product_service == "Google Kubernetes Engine"
    finally:
        set_msa_service(None)


def test_fastapi_csrf_security_headers_and_patrol_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOV_API_MODE", "MOCK")
    monkeypatch.setenv("CHAT_ENGINE", "deterministic")
    set_msa_service(MSAGovernanceService(db_path=tmp_path / "api_msa.db", seed_default=True))
    fake_api = MagicMock()
    sched = GovernancePatrolScheduler(feishu_api=fake_api, notify_chat_ids=["oc_finops_room"])
    from bot.scheduler import set_patrol_scheduler

    set_patrol_scheduler(sched)
    try:
        client = TestClient(app)
        h = client.get("/healthz")
        assert h.status_code == 200
        assert h.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in h.headers["Content-Security-Policy"]

        # POST without CSRF must be blocked (403)
        blocked = client.post("/api/patrol/run", json={"scope": "ALL", "push_to_feishu": True})
        assert blocked.status_code == 403

        # Obtain CSRF token and trigger full patrol push
        csrf = client.get("/api/session").json()["csrf_token"]
        ok = client.post(
            "/api/patrol/run",
            json={"scope": "ALL", "push_to_feishu": True},
            headers={"X-CSRF-Token": csrf},
        )
        assert ok.status_code == 200
        payload = ok.json()
        assert payload["cards_delivered"] == 3
        assert fake_api.send_card.call_count == 3
    finally:
        set_msa_service(None)
        set_patrol_scheduler(None)
