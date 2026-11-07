"""RustScan tool adapter for ultra-fast port discovery."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from app.reports.schemas import NormalizedFinding, PortResult, PortState
from app.scanners.base import BaseScannerAdapter


class RustScanAdapter(BaseScannerAdapter):
    """Adapter for RustScan fast port scanner."""

    @property
    def name(self) -> str:
        return "RustScan"

    @property
    def binary_name(self) -> str:
        return "rustscan"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [self.binary_name, "-a", target, "--batch-size", "4500", "--timeout", "1500"]

        port_range = options.get("port_range", "top1000")
        if port_range == "top100":
            args.extend(["-r", "1-1000"])
        elif port_range == "1-65535":
            args.extend(["-r", "1-65535"])

        args.append("--accessible")  # Clean machine-readable output
        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        # RustScan only discovers ports
        return []

    def parse_ports(self, output_content: str) -> List[PortResult]:
        """Extract open ports from RustScan output (e.g. 'Open 127.0.0.1:80' or '[80, 443]')."""
        ports: List[PortResult] = []
        # Pattern 1: [80, 443, 8080]
        array_match = re.search(r"\[([0-9,\s]+)\]", output_content)
        if array_match:
            raw_ports = array_match.group(1).split(",")
            for p_str in raw_ports:
                p_str = p_str.strip()
                if p_str.isdigit():
                    ports.append(PortResult(
                        port=int(p_str),
                        protocol="tcp",
                        state=PortState.OPEN,
                        discovery_source="RustScan"
                    ))
            return ports

        # Pattern 2: Open target:port
        for line in output_content.splitlines():
            line = line.strip()
            match = re.search(r"Open\s+[^:]+:(\d+)", line, re.IGNORECASE)
            if match:
                ports.append(PortResult(
                    port=int(match.group(1)),
                    protocol="tcp",
                    state=PortState.OPEN,
                    discovery_source="RustScan"
                ))

        return ports

