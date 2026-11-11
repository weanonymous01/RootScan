"""Correlation and normalization engine linking services, findings, and CVE intelligence."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from app.intelligence.cve_intelligence import CveDetails, CveIntelligence
from app.reports.schemas import (
    Confidence,
    NormalizedFinding,
    PortResult,
    ServiceResult,
    Severity,
)


class FindingCorrelator:
    """Normalizes, deduplicates, and correlates security findings with services."""

    @staticmethod
    def deduplicate_findings(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        """
        Merge identical findings detected by different tools.
        Prioritizes confirmed confidence and preserves evidence references.
        """
        merged_map: Dict[Tuple[str, Optional[int], Optional[str]], NormalizedFinding] = {}

        for f in findings:
            key = (f.title.strip().lower(), f.port, f.cve_id)
            if key not in merged_map:
                merged_map[key] = f
            else:
                existing = merged_map[key]
                # If newly seen finding has higher confidence or severity, update
                if f.confidence == Confidence.CONFIRMED and existing.confidence != Confidence.CONFIRMED:
                    existing.confidence = Confidence.CONFIRMED
                # Merge tool attribution
                if f.source_tool and f.source_tool not in existing.source_tool:
                    existing.source_tool = f"{existing.source_tool}, {f.source_tool}"
                # Merge references
                for ref in f.references:
                    if ref not in existing.references:
                        existing.references.append(ref)
                # Append evidence if different
                if f.evidence and f.evidence not in (existing.evidence or ""):
                    existing.evidence = f"{existing.evidence}\n---\n[{f.source_tool}]: {f.evidence}".strip()

        return list(merged_map.values())

    @staticmethod
    def link_findings_to_services(
        services: List[ServiceResult],
        findings: List[NormalizedFinding]
    ) -> List[NormalizedFinding]:
        """Associate unlinked findings with known exposed ports and services."""
        port_service_map = {s.port: s for s in services}

        for f in findings:
            if f.port and f.port in port_service_map:
                svc = port_service_map[f.port]
                if not f.affected_component:
                    f.affected_component = svc.service_name
                if not f.observed_version:
                    f.observed_version = svc.service_version

        return findings

    @classmethod
    async def enrich_findings_with_cve_intelligence(
        cls,
        findings: List[NormalizedFinding]
    ) -> List[NormalizedFinding]:
        """Enrich CVE findings with CISA KEV tags and advisory references."""
        for f in findings:
            if f.cve_id:
                cve_info: CveDetails = await CveIntelligence.enrich_cve(f.cve_id)
                if cve_info.in_cisa_kev:
                    # Upgrade severity and append KEV indicator
                    f.title = f"[CISA KEV Exploited] {f.title}"
                    if f.severity != Severity.CRITICAL:
                        f.severity = Severity.HIGH
                for ref in (cve_info.references or []):
                    if ref not in f.references:
                        f.references.append(ref)
        return findings

