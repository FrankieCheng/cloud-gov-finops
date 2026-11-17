# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Data models for Project-level and Organization-level GCP Quota Monitoring."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class QuotaRiskLevel(StrEnum):
    CRITICAL = "CRITICAL"  # >= 90% (or configured critical threshold)
    WARNING = "WARNING"    # >= 80% and < 90%
    HEALTHY = "HEALTHY"    # < 80%


class QuotaMetricItem(BaseModel):
    scope_type: str = "PROJECT"  # "PROJECT" or "ORGANIZATION"
    scope_id: str                # project_id or org_id
    service: str
    quota_id: str
    metric: str
    display_name: str
    region: str = "global"
    usage: float
    limit: float
    utilization_pct: float
    unit: str = "1"
    risk_level: QuotaRiskLevel = QuotaRiskLevel.HEALTHY
    is_reconciling: bool = False
    recommendation: str = ""
    quota_increase_cli: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class SecurityHygieneFinding(BaseModel):
    severity: str  # "CRITICAL", "HIGH", "WARNING"
    category: str  # "SA_KEY_EXPIRED_90D", "SA_KEY_AGING_60D", "SA_KEY_SPRAWL", "PUBLIC_IAM_EXPOSURE", "DEFAULT_SA_OVERPRIVILEGED"
    project_id: str
    principal: str
    resource_id: str = ""
    age_days: int | None = None
    summary: str
    remediation_cli: str = ""


class QuotaExceededEvent(BaseModel):
    project_id: str
    service: str
    quota_metric: str
    location: str = "global"
    exceeded_count_7d: int
    latest_exceeded_at: str = ""


class AccountHygieneReport(BaseModel):
    generated_at: str
    mode: str
    org_id: str
    projects_audited: list[str] = Field(default_factory=list)
    total_user_managed_keys: int = 0
    keys_over_90_days: int = 0
    keys_60_to_90_days: int = 0
    public_iam_bindings_count: int = 0
    overprivileged_sa_bindings_count: int = 0
    open_firewall_rules_count: int = 0
    snoozed_findings_count: int = 0
    findings: list[SecurityHygieneFinding] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class OrgQuotaPreference(BaseModel):
    name: str
    scope_type: str = "ORGANIZATION"
    scope_id: str
    service: str
    quota_id: str
    preferred_value: float
    granted_value: float | None = None
    reconciling: bool = False
    dimensions: dict[str, str] = Field(default_factory=dict)


class QuotaScanReport(BaseModel):
    generated_at: str
    mode: str
    org_id: str = ""
    projects_requested: list[str] = Field(default_factory=list)
    projects_scanned: list[str] = Field(default_factory=list)
    critical_threshold_pct: float = 90.0
    warning_threshold_pct: float = 80.0
    total_metrics_evaluated: int = 0
    critical_over_90: list[QuotaMetricItem] = Field(default_factory=list)
    warning_80_to_90: list[QuotaMetricItem] = Field(default_factory=list)
    top_utilized: list[QuotaMetricItem] = Field(default_factory=list)
    recent_exceeded_events: list[QuotaExceededEvent] = Field(default_factory=list)
    org_quota_items: list[QuotaMetricItem] = Field(default_factory=list)
    org_quota_preferences: list[OrgQuotaPreference] = Field(default_factory=list)
    org_hot_metrics_summary: list[dict[str, Any]] = Field(default_factory=list)
    access_diagnostics: list[dict[str, str]] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()
