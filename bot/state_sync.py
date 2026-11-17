# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Durable JSON state snapshot & optional GCS object sync for Cloud Run ephemeral containers."""

from __future__ import annotations

import json
import logging
import os
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from bot import config

logger = logging.getLogger(__name__)


def _gcs_target() -> tuple[str, str] | None:
    bucket = os.getenv("GOV_STATE_GCS_BUCKET", "").strip()
    obj = os.getenv("GOV_STATE_GCS_OBJECT", "cloud-gov-finops/governance_state.json").strip().lstrip("/")
    if not bucket:
        return None
    return bucket, obj


def save_state_snapshot(payload: dict[str, Any], local_path: Path | None = None) -> bool:
    """Persist governance state JSON locally and optionally write-through to GCS if configured."""
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    snap_file = local_path or (config.ensure_data_dir() / "governance_state_snapshot.json")
    try:
        tmp = snap_file.with_suffix(".tmp")
        tmp.write_bytes(raw)
        tmp.replace(snap_file)
    except Exception as exc:
        logger.debug("Local snapshot write skipped: %s", type(exc).__name__)

    target = _gcs_target()
    if not target:
        return True

    bucket, obj = target
    try:
        tok = config.get_gcp_access_token()
        url = (
            f"https://storage.googleapis.com/upload/storage/v1/b/{urllib.parse.quote(bucket)}/o"
            f"?uploadType=media&name={urllib.parse.quote(obj, safe='')}"
        )
        req = urllib.request.Request(
            url,
            data=raw,
            method="POST",
            headers={
                "Authorization": f"Bearer {tok}",
                "Content-Type": "application/json; charset=utf-8",
            },
        )
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception as exc:
        logger.warning("GCS state snapshot upload skipped: %s", type(exc).__name__)
        return False


def load_state_snapshot_from_gcs() -> dict[str, Any] | None:
    """Download persisted governance state JSON from GCS on cold container boot if configured."""
    target = _gcs_target()
    if not target:
        return None
    bucket, obj = target
    try:
        tok = config.get_gcp_access_token()
        url = (
            f"https://storage.googleapis.com/storage/v1/b/{urllib.parse.quote(bucket)}"
            f"/o/{urllib.parse.quote(obj, safe='')}?alt=media"
        )
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"Authorization": f"Bearer {tok}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.debug("GCS state snapshot download skipped: %s", type(exc).__name__)
        return None
