# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Data models for Mandatory Service Announcement (MSA) Cloud Governance."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MSACategory(StrEnum):
    RETIREMENT = "RETIREMENT"
    BREAKING_CHANGE = "BREAKING_CHANGE"
    BILLING_CHANGE = "BILLING_CHANGE"
    API_ENABLEMENT = "API_ENABLEMENT"
    MAINTENANCE = "MAINTENANCE"
    GENERAL = "GENERAL"


class MSAStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    MITIGATED = "MITIGATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MSAUrgency(StrEnum):
    OVERDUE_REVIEW = "OVERDUE_REVIEW"
    URGENT_7D = "URGENT_7D"
    UPCOMING_30D = "UPCOMING_30D"
    UPCOMING_90D = "UPCOMING_90D"
    PLANNED = "PLANNED"
    INFO_ONLY = "INFO_ONLY"
    RESOLVED = "RESOLVED"


class MSARecord(BaseModel):
    msa_id: str
    sent_date: str
    priority: str = "P3"
    subject: str
    category: MSACategory = MSACategory.GENERAL
    product_service: str = "Google Cloud"
    action_required: bool = True
    what_summary: str
    when_timeline: str
    next_steps: str
    healed_from_error: bool = False
    milestones: list[str] = Field(default_factory=list)
    primary_deadline: str = ""
    next_upcoming_deadline: str = ""
    days_to_deadline: int | None = None
    urgency: MSAUrgency = MSAUrgency.PLANNED
    status: MSAStatus = MSAStatus.OPEN
    owner: str = ""
    impacted_projects: list[str] = Field(default_factory=list)
    notes: str = ""
    updated_at: str = ""

    def to_summary_dict(self) -> dict[str, Any]:
        return self.model_dump()
