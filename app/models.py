from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ScanProfile(str, Enum):
    full = "full"
    quick = "quick"
    custom = "custom"


class ScanRequest(BaseModel):
    target: str = Field(..., description="e.g. http://127.0.0.1:8080")
    profile: ScanProfile = ScanProfile.full
    checks: Optional[list[str]] = Field(
        default=None,
        description="Only used when profile=custom. Subset of "
        "['headers','xss','sqli','traversal'].",
    )
    cookies: Optional[dict[str, str]] = Field(
        default=None,
        description="Session cookies to include with every request (e.g. {'session': 'abc123'}).",
    )
    headers: Optional[dict[str, str]] = Field(
        default=None,
        description="Extra HTTP headers to include with every request.",
    )


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    rejected = "rejected"  # out of scope


class Finding(BaseModel):
    id: str
    category: str  # sqli | xss | traversal | headers
    severity: str  # Critical | High | Medium | Low
    type: str
    endpoint: str
    parameter: str
    method: str
    url: str
    description: str
    evidence: str
    confidence: str  # High | Medium | Low


class ScanSummary(BaseModel):
    id: str
    target: str
    profile: ScanProfile
    status: ScanStatus
    created_at: str
    duration_ms: Optional[int] = None
    finding_count: Optional[int] = None


class ScanResult(ScanSummary):
    endpoints_discovered: int = 0
    parameters_mapped: int = 0
    findings: list[Finding] = []


class ScopeEntry(BaseModel):
    host: str


class ScopeList(BaseModel):
    hosts: list[str]
