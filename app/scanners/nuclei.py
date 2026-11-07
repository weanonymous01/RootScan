"""Nuclei tool adapter for automated vulnerability scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from app.parsers.nuclei_parser import NucleiParser
from app.reports.schemas import NormalizedFinding
from app.scanners.base import BaseScannerAdapter


class NucleiAdapter(BaseScannerAdapter):
    """Adapter for ProjectDiscovery Nuclei vulnerability scanner."""

    @property
    def name(self) -> str:
        return "Nuclei"

    @property
    def binary_name(self) -> str:
        return "nuclei"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        # Form safe target URL or host
        args = [self.binary_name, "-u", target, "-no-color", "-jsonl"]

        severities = options.get("nuclei_severity", ["critical", "high", "medium"])
        if severities:
            args.extend(["-severity", ",".join(severities)])

        # Rate limiting to ensure safe scanning
        rate_limit = options.get("rate_limit", 150)
        args.extend(["-rate-limit", str(rate_limit)])

        # Output path
        if output_path:
            jsonl_path = output_path.with_suffix(".jsonl")
            args.extend(["-o", str(jsonl_path)])

        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        content = output_content
        if evidence_path:
            jsonl_file = evidence_path.with_suffix(".jsonl")
            if jsonl_file.exists():
                try:
                    content = jsonl_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

        return NucleiParser.parse_jsonl(content)

