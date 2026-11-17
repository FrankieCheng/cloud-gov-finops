# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Central configuration, strict identifier validation, and GCP OAuth2 token management."""

from __future__ import annotations

import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_local_dotenv_if_present() -> None:
    if "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ:
        return
    env_file = PROJECT_ROOT / ".env"
    if not env_file.is_file():
        return
    try:
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_local_dotenv_if_present()

DATA_DIR = Path(os.getenv("GOV_DATA_DIR", str(PROJECT_ROOT / ".data"))).resolve()
DB_PATH = DATA_DIR / "governance_finops.db"

DEFAULT_ORG_ID = "123456789012"
DEFAULT_PROJECTS = "demo-core-prod,demo-edge-svc,demo-net-hub-a,demo-net-hub-b,demo-shared-dns"
DEFAULT_BILLING_TABLE = (
    "demo-core-prod.billing.gcp_billing_export_resource_v1_01ABCD_EF0123_456789"
)

_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9\-]{4,29}$")
_ORG_OR_FOLDER_ID_RE = re.compile(r"^[0-9]{6,25}$")
_BQ_TABLE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{4,64}\.[a-zA-Z0-9_]{1,128}\.[a-zA-Z0-9_]{1,256}$")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_IANA_TZ_RE = re.compile(r"^[A-Za-z0-9_+\-/]{2,64}$")

ALLOWED_FEISHU_HOSTS = frozenset({"open.feishu.cn", "open.larksuite.com"})

_ephemeral_secret: str | None = None
_token_lock = threading.Lock()
_cached_oauth_token: tuple[str, float] | None = None


def ensure_data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass
    return DATA_DIR


def get_api_mode() -> str:
    raw = os.getenv("GOV_API_MODE", "LIVE").strip().upper()
    return raw if raw in ("LIVE", "MOCK") else "LIVE"


def set_api_mode(mode: str) -> str:
    norm = (mode or "").strip().upper()
    if norm not in ("LIVE", "MOCK"):
        raise ValueError("Invalid GOV_API_MODE; expected 'LIVE' or 'MOCK'.")
    os.environ["GOV_API_MODE"] = norm
    return norm


def get_session_secret_key() -> str:
    global _ephemeral_secret
    env_val = os.getenv("SESSION_SECRET_KEY", "").strip()
    if len(env_val) >= 32:
        return env_val
    secret_file = ensure_data_dir() / "session_secret.txt"
    if secret_file.is_file():
        val = secret_file.read_text(encoding="utf-8").strip()
        if len(val) >= 32:
            return val
    if _ephemeral_secret is None:
        _ephemeral_secret = secrets.token_hex(32)
    return _ephemeral_secret


def get_org_id() -> str:
    raw = os.getenv("GOV_ORG_ID", DEFAULT_ORG_ID).strip()
    if raw.startswith("organizations/"):
        raw = raw.split("/", 1)[1].strip()
    if raw and not _ORG_OR_FOLDER_ID_RE.match(raw):
        raise ValueError(f"Invalid organization ID format: '{raw}'.")
    return raw


def validate_org_id(org_id: str) -> str:
    clean = (org_id or "").strip()
    if clean.startswith("organizations/"):
        clean = clean.split("/", 1)[1].strip()
    if not _ORG_OR_FOLDER_ID_RE.match(clean):
        raise ValueError(f"Invalid GCP organization ID '{org_id}'. Expected numeric ID.")
    return clean


def get_monitored_projects() -> list[str]:
    raw = os.getenv("GOV_PROJECTS", DEFAULT_PROJECTS)
    items = [p.strip() for p in raw.split(",") if p.strip()]
    valid: list[str] = []
    for p in items:
        if _PROJECT_ID_RE.match(p) and p not in valid:
            valid.append(p)
    return valid or ["demo-core-prod"]


def validate_project_id(project_id: str) -> str:
    clean = (project_id or "").strip()
    if clean.startswith("projects/"):
        clean = clean.split("/", 1)[1].strip()
    if not _PROJECT_ID_RE.match(clean):
        raise ValueError(f"Invalid GCP project_id '{project_id}'.")
    return clean


def get_billing_bq_project() -> str:
    return validate_project_id(os.getenv("BILLING_BQ_PROJECT", "demo-core-prod"))


def get_billing_export_tables() -> list[str]:
    raw = os.getenv("BILLING_EXPORT_TABLES", DEFAULT_BILLING_TABLE)
    tables: list[str] = []
    for t in raw.split(","):
        clean = t.strip().strip("`")
        if clean:
            tables.append(validate_bq_table_id(clean))
    return tables or [DEFAULT_BILLING_TABLE]


def validate_bq_table_id(table_id: str) -> str:
    """Strictly validate `project.dataset.table` to prevent SQL injection in table identifiers."""
    clean = (table_id or "").strip().strip("`")
    if not _BQ_TABLE_ID_RE.match(clean):
        raise ValueError(
            f"Invalid BigQuery table identifier '{table_id}'. Expected 'project.dataset.table'."
        )
    return clean


def validate_iso_date(date_str: str) -> str:
    clean = (date_str or "").strip()
    if not _ISO_DATE_RE.match(clean):
        raise ValueError(f"Invalid date '{date_str}'. Expected YYYY-MM-DD.")
    return clean


def get_billing_timezone() -> str:
    tz = os.getenv("BILLING_TIMEZONE", "Asia/Shanghai").strip()
    if not _IANA_TZ_RE.match(tz):
        return "Asia/Shanghai"
    return tz


def validate_feishu_webhook_url(url: str) -> str:
    """Enforce HTTPS and strict Feishu/Lark host allowlist to prevent SSRF."""
    clean = (url or "").strip()
    parsed = urlparse(clean)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FEISHU_HOSTS:
        raise ValueError(
            "Invalid Feishu webhook URL: only https://open.feishu.cn/... or https://open.larksuite.com/... is allowed."
        )
    return clean


def get_gcp_access_token(force_refresh: bool = False) -> str:
    """Obtain a short-lived GCP OAuth2 Bearer token via ADC first, then gcloud CLI fallback."""
    global _cached_oauth_token
    now = time.monotonic()
    with _token_lock:
        if not force_refresh and _cached_oauth_token and _cached_oauth_token[1] > now:
            return _cached_oauth_token[0]

        # 1. Standard ADC (used on Cloud Run via Metadata Server)
        if not os.getenv("PREFER_GCLOUD_CLI_TOKEN"):
            try:
                import google.auth
                import google.auth.transport.requests

                creds, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                creds.refresh(google.auth.transport.requests.Request())
                if creds.token:
                    _cached_oauth_token = (creds.token, now + 240.0)
                    return creds.token
            except Exception as exc:
                logger.debug("ADC token refresh skipped (%s); trying gcloud fallback.", type(exc).__name__)

        # 2. Local workstation gcloud CLI fallback (when active gcloud account differs from ADC)
        gcloud_bin = shutil.which("gcloud") or str(Path.home() / "google-cloud-sdk/bin/gcloud")
        if os.path.isfile(gcloud_bin):
            res = subprocess.run(
                [gcloud_bin, "auth", "print-access-token"],
                check=True,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            tok = res.stdout.strip()
            if tok:
                _cached_oauth_token = (tok, now + 240.0)
                return tok

        raise RuntimeError("Unable to obtain Google Cloud OAuth2 access token from ADC or gcloud.")
