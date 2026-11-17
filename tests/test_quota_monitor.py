# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit & integration tests for the `quota/` Project + Organization Quota Governance module."""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest

from bot import config
from quota.service import QuotaGovernanceService, build_quota_feishu_card


def test_mock_project_and_org_quota_over_90_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOV_API_MODE", "MOCK")
    svc = QuotaGovernanceService(
        org_id="123456789012",
        projects=["demo-core-prod", "demo-edge-svc"],
        critical_threshold_pct=90.0,
        warning_threshold_pct=80.0,
    )
    rep = svc.scan_all(include_org=True)
    assert rep.org_id == "123456789012"
    assert len(rep.critical_over_90) >= 3
    # Verify both PROJECT and ORGANIZATION scopes are present in >=90% alerts!
    scopes = {item.scope_type for item in rep.critical_over_90}
    assert "PROJECT" in scopes
    assert "ORGANIZATION" in scopes
    assert len(rep.warning_80_to_90) == 1
    assert rep.org_quota_preferences[0].reconciling is True

    card = build_quota_feishu_card(rep)
    assert card["header"]["template"] == "red"
    card_txt = json.dumps(card, ensure_ascii=False)
    assert "组织级" in card_txt
    assert "demo-core-prod" in card_txt
    assert "96.0%" in card_txt or "95.0%" in card_txt


def test_live_org_403_produces_actionable_iam_diagnostic_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOV_API_MODE", "LIVE")
    svc = QuotaGovernanceService(org_id="123456789012", projects=["demo-core-prod"])

    http_403 = urllib.error.HTTPError(
        url="https://cloudquotas.googleapis.com/v1/organizations/123456789012/locations/global/quotaPreferences",
        code=403,
        msg="Forbidden",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    with (
        patch.object(config, "get_gcp_access_token", return_value="fake-tok"),
        patch("quota.service.discover_org_projects_live", return_value=["demo-core-prod"]),
        patch("quota.service.scan_compute_quotas_live", return_value=[]),
        patch("quota.service.scan_serviceruntime_quotas_live", return_value=[]),
        patch("quota.scanner._gcp_get_json", side_effect=http_403),
    ):
        rep = svc.scan_all(include_org=True)

    assert rep.projects_scanned == ["demo-core-prod"]
    assert len(rep.access_diagnostics) == 1
    assert rep.access_diagnostics[0]["scope"] == "organizations/123456789012"
    assert "roles/cloudquotas.viewer" in rep.access_diagnostics[0]["message"]
