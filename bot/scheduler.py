# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Scheduled & on-demand Cloud Governance (MSA + Quota) and FinOps Billing patrol pusher."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.request
from typing import Any
from zoneinfo import ZoneInfo

from billing.service import (
    build_billing_feishu_card,
    build_finops_governance_feishu_card,
    get_billing_service,
)
from bot import config
from msa.service import build_msa_feishu_card, get_msa_service
from quota.hygiene import build_account_hygiene_feishu_card
from quota.service import build_quota_feishu_card, get_quota_service

logger = logging.getLogger(__name__)


def compute_feishu_webhook_sign(timestamp: str, webhook_secret: str) -> str:
    """Compute Feishu Custom Bot v2 HMAC-SHA256 base64 signature (`timestamp\\nsecret` as HMAC key)."""
    string_to_sign = f"{timestamp}\n{webhook_secret}"
    digest = hmac.new(string_to_sign.encode("utf-8"), b"", digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def send_feishu_webhook_card(
    webhook_url: str, card: dict[str, Any], webhook_secret: str = ""
) -> dict[str, Any]:
    safe_url = config.validate_feishu_webhook_url(webhook_url)
    payload: dict[str, Any] = {"msg_type": "interactive", "card": card}
    if webhook_secret:
        ts = str(int(time.time()))
        payload["timestamp"] = ts
        payload["sign"] = compute_feishu_webhook_sign(ts, webhook_secret)

    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        safe_url,
        data=raw,
        method="POST",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(body) if body else {}
    if isinstance(data, dict) and data.get("code", 0) not in (0, None):
        raise RuntimeError(
            f"Feishu webhook rejected card (code={data.get('code')}): {data.get('msg', 'unknown')}"
        )
    return data


def _seconds_until_next_hour(target_hour: int, tz_name: str = "Asia/Shanghai") -> float:
    try:
        tz: datetime.tzinfo = ZoneInfo(tz_name)
    except Exception:
        tz = datetime.timezone(datetime.timedelta(hours=8))
    now = datetime.datetime.now(tz)
    target = now.replace(hour=target_hour % 24, minute=0, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return max(10.0, (target - now).total_seconds())


class GovernancePatrolScheduler:
    """Executes MSA, Project/Org Quota, and Billing Export checks and pushes cards to Feishu."""

    def __init__(
        self,
        feishu_api: Any = None,
        notify_chat_ids: list[str] | None = None,
        webhook_url: str | None = None,
        webhook_secret: str | None = None,
        interval_seconds: float | None = None,
    ) -> None:
        self._api = feishu_api
        self._notify_chat_ids = (
            list(notify_chat_ids)
            if notify_chat_ids is not None
            else [
                c.strip()
                for c in os.getenv("FEISHU_GOV_NOTIFY_CHAT_IDS", "").split(",")
                if c.strip()
            ]
        )
        self._webhook_url = (
            webhook_url
            if webhook_url is not None
            else os.getenv("FEISHU_GOV_WEBHOOK_URL", "").strip()
        )
        self._webhook_secret = (
            webhook_secret
            if webhook_secret is not None
            else os.getenv("FEISHU_GOV_WEBHOOK_SECRET", "").strip()
        )
        if interval_seconds is None:
            try:
                interval_seconds = float(os.getenv("PATROL_INTERVAL_SECONDS", "0"))
            except ValueError:
                interval_seconds = 0.0
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def attach_feishu_api(self, api: Any) -> None:
        self._api = api

    def resolve_target_chats(self, extra_chat_id: str = "") -> list[str]:
        targets: list[str] = []
        if extra_chat_id and extra_chat_id.strip():
            targets.append(extra_chat_id.strip())
        for cid in self._notify_chat_ids:
            if cid not in targets:
                targets.append(cid)
        if not targets and self._api is not None and hasattr(self._api, "list_bot_chat_ids"):
            try:
                for cid in self._api.list_bot_chat_ids():
                    if cid not in targets:
                        targets.append(cid)
            except Exception as exc:
                logger.debug("Auto chat discovery skipped: %s", type(exc).__name__)
        return targets

    def deliver_cards(self, cards: list[dict[str, Any]], extra_chat_id: str = "") -> int:
        sent = 0
        chats = self.resolve_target_chats(extra_chat_id=extra_chat_id)
        if self._api is not None and hasattr(self._api, "send_card"):
            for cid in chats:
                for card in cards:
                    try:
                        self._api.send_card(cid, card)
                        sent += 1
                    except Exception as exc:
                        logger.error("Failed sending governance card to %s: %s", cid, type(exc).__name__)

        if self._webhook_url:
            for idx, card in enumerate(cards):
                if idx > 0:
                    time.sleep(0.35)
                try:
                    send_feishu_webhook_card(
                        self._webhook_url, card, webhook_secret=self._webhook_secret
                    )
                    sent += 1
                except Exception as exc:
                    logger.error(
                        "Failed sending governance webhook card: %s: %s",
                        type(exc).__name__,
                        exc,
                    )
        return sent

    def run_patrol(
        self,
        scope: str = "ALL",
        target_date: str = "",
        push_to_feishu: bool = False,
        extra_chat_id: str = "",
    ) -> dict[str, Any]:
        norm_scope = (scope or "ALL").strip().upper()
        cards: list[dict[str, Any]] = []
        out: dict[str, Any] = {"scope": norm_scope, "cards": []}

        if norm_scope in ("EXECUTIVE", "EXEC_HEALTH"):
            from bot.agent import (
                build_executive_health_feishu_card,
                compute_executive_health_report,
            )

            exec_rep = compute_executive_health_report()
            out["executive_health"] = exec_rep
            cards.append(build_executive_health_feishu_card(exec_rep))

        if norm_scope in ("ALL", "EXECUTIVE", "MSA"):
            msa_svc = get_msa_service()
            try:
                msa_svc.auto_correlate_impacted_projects()
            except Exception as exc:
                logger.debug("MSA auto-correlate skipped during patrol: %s", type(exc).__name__)
            msa_radar = msa_svc.get_governance_radar()
            msa_card = build_msa_feishu_card(msa_radar)
            out["msa"] = msa_radar
            cards.append(msa_card)

        if norm_scope in ("ALL", "EXECUTIVE", "QUOTA"):
            quota_rep = get_quota_service().scan_all(include_org=True)
            quota_card = build_quota_feishu_card(quota_rep)
            out["quota"] = quota_rep.to_dict()
            cards.append(quota_card)

        if norm_scope in ("EXECUTIVE", "HYGIENE"):
            hyg_rep = get_quota_service().audit_hygiene()
            out["hygiene"] = hyg_rep.to_dict()
            cards.append(build_account_hygiene_feishu_card(hyg_rep))

        if norm_scope in ("ALL", "EXECUTIVE", "BILLING"):
            bill_rep = get_billing_service().generate_daily_report(target_date=target_date)
            bill_card = build_billing_feishu_card(bill_rep)
            out["billing"] = bill_rep.to_dict()
            cards.append(bill_card)

        if norm_scope in ("EXECUTIVE", "FINOPS_GOV"):
            fgov_rep = get_billing_service().generate_finops_governance_report(
                as_of_date=target_date
            )
            out["finops_governance"] = fgov_rep.to_dict()
            cards.append(build_finops_governance_feishu_card(fgov_rep))

        out["cards"] = cards
        out["cards_delivered"] = (
            self.deliver_cards(cards, extra_chat_id=extra_chat_id) if push_to_feishu else 0
        )
        return out

    def start_background(self) -> threading.Thread | None:
        daily_hour_raw = os.getenv("PATROL_DAILY_HOUR", "").strip()
        daily_hour: int | None = None
        if daily_hour_raw:
            try:
                daily_hour = int(daily_hour_raw) % 24
            except ValueError:
                daily_hour = None

        if self.interval_seconds <= 0 and daily_hour is None:
            return None
        if self._thread is not None and self._thread.is_alive():
            return self._thread
        self._stop_event.clear()
        run_on_startup = os.getenv("PATROL_RUN_ON_STARTUP", "false").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        default_scope = os.getenv("PATROL_DEFAULT_SCOPE", "ALL").strip().upper() or "ALL"
        tz_name = config.get_billing_timezone()

        def _loop() -> None:
            logger.info(
                "GovernancePatrolScheduler started (scope=%s daily_hour=%s tz=%s interval=%ss run_on_startup=%s).",
                default_scope,
                daily_hour,
                tz_name,
                self.interval_seconds,
                run_on_startup,
            )
            if run_on_startup and not self._stop_event.is_set():
                try:
                    self.run_patrol(scope=default_scope, push_to_feishu=True)
                except Exception as exc:
                    logger.error("Startup patrol error: %s", type(exc).__name__)

            while not self._stop_event.is_set():
                wait_sec = (
                    _seconds_until_next_hour(daily_hour, tz_name)
                    if daily_hour is not None
                    else self.interval_seconds
                )
                if self._stop_event.wait(wait_sec):
                    break
                try:
                    self.run_patrol(scope=default_scope, push_to_feishu=True)
                except Exception as exc:
                    logger.error("Patrol loop error: %s", type(exc).__name__)

        self._thread = threading.Thread(target=_loop, name="gov-patrol-scheduler", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        self._stop_event.set()


_scheduler_instance: GovernancePatrolScheduler | None = None


def get_patrol_scheduler() -> GovernancePatrolScheduler:
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = GovernancePatrolScheduler()
    return _scheduler_instance


def set_patrol_scheduler(sched: GovernancePatrolScheduler | None) -> None:
    global _scheduler_instance
    _scheduler_instance = sched
