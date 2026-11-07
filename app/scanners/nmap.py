"""Nmap tool adapter for network and port scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.parsers.nmap_parser import NmapParser
from app.reports.schemas import NormalizedFinding, PortResult, ServiceResult
from app.scanners.base import BaseScannerAdapter


class NmapAdapter(BaseScannerAdapter):
    """Adapter for Nmap network scanner."""

    @property
    def name(self) -> str:
        return "Nmap"

    @property
    def binary_name(self) -> str:
        return "nmap"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [self.binary_name, "-sV", "-Pn", "--open"]

        port_range = options.get("port_range", "top100")
        if port_range == "top100":
            args.extend(["-F"])  # Fast scan (top 100 ports)
        elif port_range == "top1000":
            args.extend(["--top-ports", "1000"])
        elif port_range == "1-65535":
            args.extend(["-p-"])
        elif isinstance(port_range, str) and ("," in port_range or "-" in port_range):
            args.extend(["-p", port_range])

        # If timing template specified
        args.extend(["-T4"])

        # XML output flag
        if output_path:
            xml_path = output_path.with_suffix(".xml")
            args.extend(["-oX", str(xml_path)])

        args.append(target)
        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        xml_content = output_content
        if evidence_path:
            xml_file = evidence_path.with_suffix(".xml")
            if xml_file.exists():
                try:
                    xml_content = xml_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

        _, _, findings = NmapParser.parse_xml(xml_content)
        return findings

    async def run_discovery(
        self,
        scan_id: str,
        target: str,
        options: Dict[str, Any],
        evidence_dir: Optional[Path] = None,
        timeout_seconds: int = 600
    ) -> Tuple[List[PortResult], List[ServiceResult], List[NormalizedFinding]]:
        """Run Nmap and extract both ports, services, and script findings."""
        output_file = None
        if evidence_dir:
            output_file = evidence_dir / "nmap.raw"

        args = self.build_command(target, options, output_path=output_file)
        res = await self.task_manager.execute_tool(
            scan_id=scan_id,
            tool_name=self.name,
            args=args,
            timeout_seconds=timeout_seconds
        )

        xml_content = res.stdout
        if output_file:
            xml_file = output_file.with_suffix(".xml")
            if xml_file.exists():
                try:
                    xml_content = xml_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

        return NmapParser.parse_xml(xml_content)

