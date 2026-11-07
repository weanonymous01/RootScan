"""Nuclei JSONL output parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from app.reports.schemas import Confidence, NormalizedFinding, Severity


class NucleiParser:
    """Parses Nuclei JSONL output into normalized security findings."""

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    @classmethod
    def parse_jsonl(cls, jsonl_content: str) -> List[NormalizedFinding]:
        findings: List[NormalizedFinding] = []
        if not jsonl_content or not jsonl_content.strip():
            return findings

        for line in jsonl_content.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            raw_sev = str(info.get("severity", "info")).lower()
            severity = cls.SEVERITY_MAP.get(raw_sev, Severity.INFO)
            
            # Extract CVE
            cve_id = None
            classification = info.get("classification", {})
            if classification and "cve-id" in classification:
                cve_val = classification["cve-id"]
                if isinstance(cve_val, list) and cve_val:
                    cve_id = cve_val[0]
                elif isinstance(cve_val, str):
                    cve_id = cve_val

            template_id = data.get("template-id", "unknown-template")
            title = info.get("name", template_id)
            matched_at = data.get("matched-at", "")
            description = info.get("description", "")
            remediation = info.get("remediation", "")
            references = info.get("reference", [])
            if isinstance(references, str):
                references = [references]

            evidence = f"Matched at: {matched_at}\n{description}".strip()
            extracted = data.get("extracted-results", [])
            if extracted:
                evidence += f"\nExtracted: {extracted}"

            findings.append(NormalizedFinding(
                id=template_id,
                title=title,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                cve_id=cve_id,
                source_tool="Nuclei",
                evidence=evidence,
                references=references,
                remediation=remediation or None
            ))

        return findings

