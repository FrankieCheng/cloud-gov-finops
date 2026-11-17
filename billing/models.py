# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Data models for FinOps BigQuery Billing Export analysis and anomaly attribution."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SkuDriver(BaseModel):
    service: str
    sku: str
    location: str = "global"
    target_net_cost: float
    baseline_net_cost: float
    delta_net_cost: float
    target_gross_cost: float = 0.0


class ProjectDailySpend(BaseModel):
    project_id: str
    project_name: str
    currency: str = "USD"
    gross_cost: float
    credits_amount: float
    net_cost: float
    prior_day_net_cost: float = 0.0
    dod_delta_net: float = 0.0
    dod_pct_net: float | None = None
    avg_7d_net_cost: float = 0.0
    baseline_delta_net: float = 0.0
    baseline_pct_net: float | None = None
    z_score: float = 0.0
    mtd_net_cost: float = 0.0
    active_services: int = 0


class AnomalyFinding(BaseModel):
    rank: int
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "WATCH"
    anomaly_type: str  # "COST_SPIKE", "COST_DROP", "CREDIT_CHANGE", "NEW_SPEND", "INTRADAY_SPIKE"
    project_id: str
    project_name: str
    usage_date: str
    currency: str = "USD"
    net_cost: float
    gross_cost: float
    prior_day_net_cost: float
    avg_7d_net_cost: float
    dod_delta_net: float
    dod_pct_net: float | None = None
    baseline_delta_net: float
    baseline_pct_net: float | None = None
    z_score: float
    anomaly_score: float
    reason_summary: str
    top_sku_drivers: list[SkuDriver] = Field(default_factory=list)


class ResourceCostItem(BaseModel):
    project_id: str
    service: str
    resource_name: str
    location: str = "global"
    net_cost_7d: float
    gross_cost_7d: float = 0.0
    has_labels: bool = False


class IdleWasteItem(BaseModel):
    project_id: str
    category: str  # "IDLE_EXTERNAL_IP", "UNATTACHED_DISK", "STOPPED_VM", "AGING_SNAPSHOT"
    resource_name: str
    location: str
    detail: str
    estimated_monthly_waste_usd: float
    cleanup_cli: str


class CreditCategorySummary(BaseModel):
    credit_type: str
    total_amount_usd: float
    share_of_savings_pct: float = 0.0


class ProjectLabelCompliance(BaseModel):
    project_id: str
    net_cost_7d: float
    unlabeled_net_cost_7d: float
    unlabeled_pct: float


class FinOpsGovernanceReport(BaseModel):
    generated_at: str
    mode: str
    as_of_date: str
    currency: str = "USD"
    # 1. EOM Forecast & Budget Pacing
    monthly_budget_usd: float
    mtd_net_cost_usd: float
    avg_7d_daily_net_usd: float
    days_elapsed: int
    days_in_month: int
    eom_forecast_net_usd: float
    budget_utilization_pct: float
    forecast_budget_pct: float
    budget_status: str  # "HEALTHY", "WARNING", "EXCEEDED"
    # 2. Effective Savings Rate (ESR) & Credits
    mtd_list_cost_usd: float = 0.0
    mtd_gross_cost_usd: float = 0.0
    mtd_total_savings_usd: float = 0.0
    effective_savings_rate_pct: float = 0.0
    credit_breakdown: list[CreditCategorySummary] = Field(default_factory=list)
    # 3. Label / Tag Cost Allocation Compliance
    net_cost_7d_usd: float = 0.0
    unlabeled_net_cost_7d_usd: float = 0.0
    unlabeled_spend_pct: float = 0.0
    label_compliance_pct: float = 100.0
    project_label_gaps: list[ProjectLabelCompliance] = Field(default_factory=list)
    # 4. Top Costly Individual Resources
    top_resources_7d: list[ResourceCostItem] = Field(default_factory=list)
    # 5. Live Idle / Zombie Resource Waste
    idle_waste_items: list[IdleWasteItem] = Field(default_factory=list)
    estimated_monthly_waste_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class DailyBillingReport(BaseModel):
    generated_at: str
    mode: str
    billing_tables: list[str]
    timezone: str = "Asia/Shanghai"
    target_date: str
    currency: str = "USD"
    total_gross_cost: float = 0.0
    total_credits: float = 0.0
    total_net_cost: float = 0.0
    prior_day_total_net_cost: float = 0.0
    total_dod_delta_net: float = 0.0
    total_dod_pct_net: float | None = None
    mtd_total_net_cost: float = 0.0
    monthly_budget_usd: float = 0.0
    eom_forecast_net_cost: float = 0.0
    forecast_budget_pct: float | None = None
    intraday_date: str = ""
    intraday_total_net_cost: float = 0.0
    projects_summary: list[ProjectDailySpend] = Field(default_factory=list)
    suspected_anomalies: list[AnomalyFinding] = Field(default_factory=list)
    intraday_alerts: list[AnomalyFinding] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()
