"""Unified Pydantic schemas for RootScan assessment data and normalization."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetModel(BaseModel):
    raw_input: str
    normalized_target: str
    target_type: str  # ipv4, ipv6, domain
    resolved_ips: List[str] = Field(default_factory=list)
    is_private: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PortState(str, Enum):
    OPEN = "open"
    FILTERED = "filtered"
    CLOSED = "closed"
    UNFILTERED = "unfiltered"


def _collect_unique_sources(primary: Optional[str], extra: List[str]) -> List[str]:
    """Split comma-separated source names and return unique ordered tool names."""
    tools: List[str] = []
    for raw in [primary or "", *extra]:
        for part in str(raw).split(","):
            name = part.strip()
            if name and name not in tools:
                tools.append(name)
    return tools


class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: PortState = PortState.OPEN
    discovery_source: str
    source_tools: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    def all_sources(self) -> List[str]:
        """Return ordered unique list of tools that discovered this port."""
        return _collect_unique_sources(self.discovery_source, self.source_tools)


class ServiceResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    source_tool: str = "nmap"
    source_tools: List[str] = Field(default_factory=list)

    def all_sources(self) -> List[str]:
        """Return ordered unique list of tools that identified or enriched this service."""
        return _collect_unique_sources(self.source_tool, self.source_tools)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    HYPOTHESIS = "hypothesis"


class NormalizedFinding(BaseModel):
    id: Optional[str] = None
    title: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.SUSPECTED
    cve_id: Optional[str] = None
    affected_component: Optional[str] = None
    observed_version: Optional[str] = None
    source_tool: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    evidence: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    raw_output: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanMetadata(BaseModel):
    scan_id: str
    target: str
    target_type: str
    profile: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    status: str = "running"
    rootscan_version: str = "1.0.0"


class FinalReport(BaseModel):
    metadata: ScanMetadata
    target: TargetModel
    reconnaissance: Dict[str, Any] = Field(default_factory=dict)
    ports: List[PortResult] = Field(default_factory=list)
    services: List[ServiceResult] = Field(default_factory=list)
    findings: List[NormalizedFinding] = Field(default_factory=list)
    tool_summary: Dict[str, Any] = Field(default_factory=dict)
    skipped_stages: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class AIAnalysisReport(BaseModel):
    scan_id: str
    model: str
    executive_summary: str
    attack_surface_analysis: str
    vulnerability_explanation: str
    exploit_intelligence: str
    attack_path_analysis: str
    risk_prioritization: str
    recommendations: str
    limitations: str
    conclusion: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

