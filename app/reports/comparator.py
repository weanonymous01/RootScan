"""Assessment comparator for diffing historical scan reports (FR-18)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from app.reports.schemas import FinalReport, NormalizedFinding, PortResult, ServiceResult


@dataclass
class ScanComparisonResult:
    base_scan_id: str
    target_scan_id: str
    target: str
    new_open_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    new_findings: List[NormalizedFinding] = field(default_factory=list)
    resolved_findings: List[NormalizedFinding] = field(default_factory=list)
    persistent_findings: List[NormalizedFinding] = field(default_factory=list)
    service_version_changes: List[Dict[str, Any]] = field(default_factory=list)
    risk_delta: str = "UNCHANGED"  # INCREASED, DECREASED, UNCHANGED


class ReportComparator:
    """Computes technical diffs between two RootScan assessments."""

    @classmethod
    def compare(cls, older_report: FinalReport, newer_report: FinalReport) -> ScanComparisonResult:
        old_ports: Set[int] = {p.port for p in older_report.ports}
        new_ports: Set[int] = {p.port for p in newer_report.ports}

        new_open = sorted(list(new_ports - old_ports))
        closed = sorted(list(old_ports - new_ports))

        # Compare services
        old_services = {s.port: s for s in older_report.services}
        new_services = {s.port: s for s in newer_report.services}
        version_changes = []

        for port, new_svc in new_services.items():
            if port in old_services:
                old_svc = old_services[port]
                if old_svc.service_version != new_svc.service_version:
                    version_changes.append({
                        "port": port,
                        "service": new_svc.service_name,
                        "old_version": old_svc.service_version or "unknown",
                        "new_version": new_svc.service_version or "unknown",
                    })

        # Compare findings
        old_f_map = {f.title.strip().lower(): f for f in older_report.findings}
        new_f_map = {f.title.strip().lower(): f for f in newer_report.findings}

        new_findings: List[NormalizedFinding] = [
            f for key, f in new_f_map.items() if key not in old_f_map
        ]
        resolved_findings: List[NormalizedFinding] = [
            f for key, f in old_f_map.items() if key not in new_f_map
        ]
        persistent_findings: List[NormalizedFinding] = [
            f for key, f in new_f_map.items() if key in old_f_map
        ]

        # Calculate risk direction
        if len(new_findings) > len(resolved_findings) or len(new_open) > len(closed):
            risk_delta = "INCREASED"
        elif len(resolved_findings) > len(new_findings) or len(closed) > len(new_open):
            risk_delta = "DECREASED"
        else:
            risk_delta = "UNCHANGED"

        return ScanComparisonResult(
            base_scan_id=older_report.metadata.scan_id,
            target_scan_id=newer_report.metadata.scan_id,
            target=newer_report.target.normalized_target,
            new_open_ports=new_open,
            closed_ports=closed,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            service_version_changes=version_changes,
            risk_delta=risk_delta
        )
