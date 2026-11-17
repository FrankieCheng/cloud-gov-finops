# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Hardened FastAPI Gateway for Cloud Governance (MSA + Quota) & FinOps Billing Bot."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse

from billing.service import get_billing_service
from bot import config
from bot.agent import (
    adk_app,
    build_cards_for_tool_types,
    compute_executive_health_report,
    run_deterministic_gov_turn,
)
from bot.feishu_bot import start_gov_feishu_bot_if_configured
from bot.scheduler import get_patrol_scheduler
from msa.service import get_msa_service
from quota.service import get_quota_service

logger = logging.getLogger(__name__)

SESSION_COOKIE = "__Host-gov_session"
SESSION_TTL_SECONDS = 3600 * 4
ALLOWED_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}

CSP_VALUE = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
)

_SESSIONS: dict[str, tuple[str, float]] = {}  # session_id -> (csrf_token, expires_at)
_adk_sessions = InMemorySessionService()
_adk_runner = Runner(app=adk_app, session_service=_adk_sessions)
_known_adk_sessions: set[tuple[str, str]] = set()


def _sign(val: str) -> str:
    key = config.get_session_secret_key().encode("utf-8")
    sig = hmac.new(key, val.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{val}.{sig}"


def _verify(signed: str) -> str | None:
    if not signed or "." not in signed:
        return None
    val, sig = signed.rsplit(".", 1)
    key = config.get_session_secret_key().encode("utf-8")
    exp = hmac.new(key, val.encode("utf-8"), hashlib.sha256).hexdigest()
    return val if hmac.compare_digest(sig, exp) else None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.method.upper() not in ALLOWED_METHODS:
            return JSONResponse(status_code=405, content={"error": "Method not allowed."})
        resp = await call_next(request)
        resp.headers.setdefault("Content-Security-Policy", CSP_VALUE)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp


def require_csrf(request: Request) -> str:
    now = time.time()
    csrf_hdr = request.headers.get("X-CSRF-Token", "").strip()
    if not csrf_hdr:
        raise HTTPException(status_code=403, detail="Missing X-CSRF-Token header.")

    raw_cookie = request.cookies.get(SESSION_COOKIE, "")
    sid = _verify(raw_cookie) if raw_cookie else None
    if not sid:
        verified_hdr = _verify(csrf_hdr)
        if verified_hdr and ":" in verified_hdr:
            sid = verified_hdr.split(":", 1)[0]
    if not sid or sid not in _SESSIONS:
        raise HTTPException(status_code=403, detail="Invalid or expired session.")
    expected_csrf, exp_at = _SESSIONS[sid]
    if exp_at <= now or not hmac.compare_digest(expected_csrf, csrf_hdr):
        raise HTTPException(status_code=403, detail="CSRF token mismatch.")
    return sid


async def run_gov_agent_turn(user_id: str, session_id: str, message: str) -> dict[str, Any]:
    engine = os.getenv("CHAT_ENGINE", "llm").strip().lower()
    if engine == "deterministic":
        return run_deterministic_gov_turn(message)

    key = (user_id, session_id)
    if key not in _known_adk_sessions:
        existing = await _adk_sessions.get_session(
            app_name="cloud_gov_finops", user_id=user_id, session_id=session_id
        )
        if existing is None:
            await _adk_sessions.create_session(
                app_name="cloud_gov_finops", user_id=user_id, session_id=session_id
            )
        _known_adk_sessions.add(key)

    date_m = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", message or "")
    target_date = date_m.group(1) if date_m else ""
    content = types.Content(role="user", parts=[types.Part.from_text(text=message)])

    reply_parts: list[str] = []
    card_types: list[str] = []
    tool_calls: list[dict[str, Any]] = []

    async for event in _adk_runner.run_async(
        user_id=user_id, session_id=session_id, new_message=content
    ):
        if not (event.content and event.content.parts):
            continue
        for part in event.content.parts:
            if part.function_call:
                tool_calls.append(
                    {"tool": part.function_call.name, "args": dict(part.function_call.args or {})}
                )
            elif part.function_response:
                resp = part.function_response.response or {}
                if isinstance(resp, dict) and resp.get("card_type"):
                    card_types.append(str(resp["card_type"]))
            elif part.text and event.author != "user":
                reply_parts.append(part.text)

    cards = build_cards_for_tool_types(
        card_types,
        target_date=target_date,
        interactive_callbacks=user_id.startswith("feishu:"),
    )
    return {
        "reply": "\n".join(reply_parts).strip() or "（未返回文本回复）",
        "tool_calls": tool_calls,
        "cards": cards,
    }


@asynccontextmanager
async def lifespan(_app: FastAPI):
    loop = asyncio.get_running_loop()
    start_gov_feishu_bot_if_configured(turn_runner=run_gov_agent_turn, main_loop=loop)
    get_patrol_scheduler().start_background()
    yield
    get_patrol_scheduler().stop()


app = FastAPI(
    title="Google Cloud Governance & FinOps Agent",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(SecurityHeadersMiddleware)


class MSAUpdatePayload(BaseModel):
    msa_id_or_keyword: str = Field(..., min_length=2, max_length=128)
    status: str = Field(default="")
    owner: str = Field(default="", max_length=128)
    impacted_projects: str = Field(default="", max_length=512)
    notes: str = Field(default="", max_length=1000)


class PatrolTriggerPayload(BaseModel):
    scope: str = Field(default="ALL")
    target_date: str = Field(default="")
    push_to_feishu: bool = Field(default=True)


class ChatPayload(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    session_id: str = Field(default="web-default", max_length=128)


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "cloud-gov-finops-agent",
        "mode": config.get_api_mode(),
        "org_id": config.get_org_id(),
        "monitored_projects": config.get_monitored_projects(),
    }


@app.get("/api/session")
async def create_or_get_session(response: Response) -> dict[str, str]:
    sid = secrets.token_urlsafe(32)
    csrf = _sign(f"{sid}:{secrets.token_urlsafe(24)}")
    _SESSIONS[sid] = (csrf, time.time() + SESSION_TTL_SECONDS)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=_sign(sid),
        max_age=SESSION_TTL_SECONDS,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return {"csrf_token": csrf}


@app.get("/api/msa")
async def api_list_msa(status_filter: str = Query(default="ALL"), query: str = Query(default="")) -> dict[str, Any]:
    svc = get_msa_service()
    radar = svc.get_governance_radar()
    if query or status_filter.upper() != "ALL":
        radar["items"] = [
            r.to_summary_dict() for r in svc.list_msas(status_filter=status_filter, query=query)
        ]
    return radar


@app.post("/api/msa/status")
async def api_update_msa(body: MSAUpdatePayload, _sid: str = Depends(require_csrf)) -> dict[str, Any]:
    try:
        updated = get_msa_service().update_msa_status(
            msa_id_or_keyword=body.msa_id_or_keyword,
            status=body.status or None,
            owner=body.owner or None,
            impacted_projects=body.impacted_projects or None,
            notes=body.notes or None,
        )
        return {"status": "success", "msa": updated.to_summary_dict()}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/quota/scan")
async def api_scan_quotas(
    project_id: str = Query(default=""),
    include_org: bool = Query(default=True),
    critical_threshold_pct: float = Query(default=90.0, ge=1.0, le=100.0),
) -> dict[str, Any]:
    try:
        return get_quota_service().scan_all(
            project_filter=project_id,
            include_org=include_org,
            critical_threshold_pct=critical_threshold_pct,
        ).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/billing/daily")
async def api_daily_billing(
    target_date: str = Query(default=""),
    top_n: int = Query(default=5, ge=1, le=25),
) -> dict[str, Any]:
    try:
        return get_billing_service().generate_daily_report(
            target_date=target_date, top_n=top_n
        ).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/billing/governance")
async def api_billing_governance(
    as_of_date: str = Query(default=""),
    monthly_budget_usd: float = Query(default=0.0, ge=0.0, le=10_000_000.0),
) -> dict[str, Any]:
    try:
        return get_billing_service().generate_finops_governance_report(
            monthly_budget_usd=monthly_budget_usd if monthly_budget_usd > 0 else None,
            as_of_date=as_of_date,
        ).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/quota/hygiene")
async def api_quota_hygiene() -> dict[str, Any]:
    return get_quota_service().audit_hygiene().to_dict()


@app.post("/api/msa/correlate")
async def api_msa_correlate(_sid: str = Depends(require_csrf)) -> dict[str, Any]:
    return get_msa_service().auto_correlate_impacted_projects()


class AlertSnoozePayload(BaseModel):
    finding_key: str = Field(..., min_length=2, max_length=256)
    reason: str = Field(default="", max_length=500)
    days: int = Field(default=7, ge=1, le=90)


@app.get("/api/billing/architecture")
async def api_billing_architecture(
    lookback_days: int = Query(default=14, ge=7, le=30),
) -> dict[str, Any]:
    return get_billing_service().analyze_architecture(lookback_days=lookback_days)


@app.get("/api/msa/export.tsv", response_class=PlainTextResponse)
async def api_export_msa_tsv() -> Response:
    tsv_data = get_msa_service().export_ledger_tsv()
    return PlainTextResponse(
        content=tsv_data,
        media_type="text/tab-separated-values; charset=utf-8",
    )


@app.get("/api/msa/audit-log")
async def api_msa_audit_log(limit: int = Query(default=20, ge=1, le=100)) -> dict[str, Any]:
    return {
        "audit_events": get_msa_service().list_audit_events(limit=limit),
        "active_snoozes": get_msa_service().list_active_snoozes(),
    }


@app.post("/api/alerts/snooze")
async def api_snooze_alert(
    body: AlertSnoozePayload, _sid: str = Depends(require_csrf)
) -> dict[str, Any]:
    from bot.cache import invalidate_cache

    entry = get_msa_service().snooze_finding(
        finding_key=body.finding_key, reason=body.reason, days=body.days
    )
    invalidate_cache()
    return {"status": "success", "snooze": entry}


@app.get("/api/executive/health")
async def api_executive_health(
    monthly_budget_usd: float = Query(default=0.0, ge=0.0, le=10_000_000.0),
) -> dict[str, Any]:
    return compute_executive_health_report(monthly_budget_usd=monthly_budget_usd)


@app.post("/api/patrol/run")
async def api_run_patrol(body: PatrolTriggerPayload, _sid: str = Depends(require_csrf)) -> dict[str, Any]:
    try:
        return get_patrol_scheduler().run_patrol(
            scope=body.scope,
            target_date=body.target_date,
            push_to_feishu=body.push_to_feishu,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/chat")
async def api_chat(body: ChatPayload, sid: str = Depends(require_csrf)) -> dict[str, Any]:
    return await run_gov_agent_turn(f"web:{sid[:12]}", body.session_id, body.message)
