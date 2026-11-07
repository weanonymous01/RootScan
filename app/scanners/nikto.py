"""Nikto tool adapter for web server assessment and misconfiguration scanning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.reports.schemas import Confidence, NormalizedFinding, Severity
from app.scanners.base import BaseScannerAdapter


class NiktoAdapter(BaseScannerAdapter):
    """Adapter for Nikto web server scanner."""

    @property
    def name(self) -> str:
        return "Nikto"

    @property
    def binary_name(self) -> str:
        return "nikto"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [self.binary_name, "-h", target, "-nointeractive"]

        if output_path:
            json_path = output_path.with_suffix(".json")
            args.extend(["-Format", "json", "-output", str(json_path)])

        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        findings: List[NormalizedFinding] = []
        content = output_content

        if evidence_path:
            json_file = evidence_path.with_suffix(".json")
            if json_file.exists():
                try:
                    content = json_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

        if not content or not content.strip():
            return findings

        try:
            data = json.loads(content)
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                msg = item.get("msg", "")
                osvdb = item.get("OSVDB", "")
                method = item.get("method", "GET")
                url_path = item.get("url", "")

                severity = Severity.INFO
                if any(k in msg.lower() for k in ("vulnerable", "remote code execution", "traversal", "sql injection")):
                    severity = Severity.HIGH
                elif any(k in msg.lower() for k in ("outdated", "deprecated", "x-frame-options", "hsts", "sensitive")):
                    severity = Severity.MEDIUM

                findings.append(NormalizedFinding(
                    title=f"Nikto: {msg[:80]}",
                    severity=severity,
                    confidence=Confidence.SUSPECTED,
                    source_tool="Nikto",
                    evidence=f"Method: {method} {url_path}\nMessage: {msg}\nOSVDB: {osvdb}".strip(),
                    references=[f"https://vulners.com/osvdb/OSVDB:{osvdb}"] if osvdb else []
                ))
        except Exception:
            # Fallback text parsing for older Nikto versions
            for line in content.splitlines():
                if "+ " in line and ("OSVDB" in line or "Server" in line or "header" in line):
                    findings.append(NormalizedFinding(
                        title=f"Nikto: {line.strip('+ ').strip()[:80]}",
                        severity=Severity.INFO,
                        confidence=Confidence.SUSPECTED,
                        source_tool="Nikto",
                        evidence=line.strip()
                    ))

        return findings

