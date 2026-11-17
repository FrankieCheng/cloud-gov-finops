# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Thread-safe TTL cache to avoid redundant 10-project GCP API scans within a patrol or chat window."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

T = TypeVar("T")

_lock = threading.Lock()
_store: dict[str, tuple[Any, float]] = {}


def get_default_ttl() -> float:
    # Disable cross-test caching automatically in MOCK mode unless explicitly configured
    if os.getenv("GOV_API_MODE", "LIVE").strip().upper() == "MOCK":
        return float(os.getenv("GOV_MOCK_CACHE_TTL_SECONDS", "0.0"))
    try:
        return max(0.0, float(os.getenv("GOV_CACHE_TTL_SECONDS", "90.0")))
    except ValueError:
        return 90.0


def cached_call(
    key: str,
    fn: Callable[[], T],
    ttl_seconds: float | None = None,
    force_refresh: bool = False,
) -> T:
    ttl = get_default_ttl() if ttl_seconds is None else ttl_seconds
    if ttl <= 0:
        return fn()

    now = time.monotonic()
    if not force_refresh:
        with _lock:
            hit = _store.get(key)
            if hit is not None and hit[1] > now:
                return hit[0]

    val = fn()
    with _lock:
        _store[key] = (val, time.monotonic() + ttl)
    return val


def invalidate_cache(prefix: str = "") -> None:
    with _lock:
        if not prefix:
            _store.clear()
        else:
            for k in [k for k in _store if k.startswith(prefix)]:
                _store.pop(k, None)
