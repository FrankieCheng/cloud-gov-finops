# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Auto-correlates MSA announcements against active GCP services per project from Billing Export."""

from __future__ import annotations

import datetime
import logging
from collections import defaultdict

from billing.analyzer import _make_bq_client
from bot import config
from msa.models import MSARecord

logger = logging.getLogger(__name__)


def fetch_active_services_per_project() -> dict[str, set[str]]:
    """Return `{project_id: {lowercased_service_descriptions}}` over the past 30 days."""
    if config.get_api_mode() == "MOCK":
        return {
            "demo-core-prod": {
                "vertex ai",
                "compute engine",
                "cloud sql",
                "cloud run",
                "bigquery",
                "networking",
                "cloud dns",
                "firebase",
            },
            "demo-edge-svc": {"compute engine", "networking", "cloud run"},
            "demo-shared-dns": {"cloud dns", "networking"},
        }

    from google.cloud import bigquery

    tables = [config.validate_bq_table_id(t) for t in config.get_billing_export_tables()]
    part_start = (
        datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(days=30)
    ).isoformat()
    branches = " UNION ALL ".join(
        f"""
        SELECT
          project.id AS pid,
          LOWER(service.description) AS svc
        FROM `{tbl}`
        WHERE _PARTITIONTIME >= TIMESTAMP(@part_start)
          AND project.id IS NOT NULL
          AND ABS(cost) > 0
        """
        for tbl in tables
    )
    sql = f"SELECT DISTINCT pid, svc FROM ({branches}) WHERE pid IS NOT NULL AND svc IS NOT NULL"
    client = _make_bq_client()
    rows = client.query(
        sql,
        job_config=bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("part_start", "STRING", part_start)]
        ),
    ).result()

    mapping: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        mapping[str(r["pid"])].add(str(r["svc"]))
    return dict(mapping)


def match_msa_to_projects(rec: MSARecord, active_services_by_proj: dict[str, set[str]]) -> list[str]:
    """Match a single MSARecord against active project service footprints."""
    prod = (rec.product_service or "").lower()
    text = f"{rec.subject} {rec.what_summary}".lower()

    matched: list[str] = []
    for pid, svcs in sorted(active_services_by_proj.items()):
        joined = " | ".join(svcs)
        hit = False
        if "vertex" in prod or "gemini" in prod:
            hit = any(k in joined for k in ("vertex", "gemini", "ai platform", "generativelanguage"))
        elif "cloud sql" in prod:
            hit = "cloud sql" in joined
        elif "cloud dns" in prod:
            hit = "dns" in joined or "dns" in pid.lower() or "networking" in joined
        elif "backup and dr" in prod or "backup and dr" in text:
            hit = any(k in joined for k in ("compute engine", "cloud sql", "alloydb", "filestore"))
        elif "load balanc" in prod or "passthrough network load balanc" in text:
            hit = "networking" in joined or "compute engine" in joined
        elif "firebase" in prod:
            hit = any(k in joined for k in ("firebase", "firestore", "identity platform"))
        elif "kubernetes" in prod or "gke" in prod:
            hit = "kubernetes" in joined
        elif "bigquery" in prod:
            hit = "bigquery" in joined
        elif "compute engine" in prod:
            hit = "compute engine" in joined

        if hit:
            matched.append(pid)
    return matched
