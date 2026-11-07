"""Naabu tool adapter for fast port discovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.reports.schemas import NormalizedFinding, PortResult, PortState
from app.scanners.base import BaseScannerAdapter


class NaabuAdapter(BaseScannerAdapter):
    """Adapter for ProjectDiscovery Naabu port discovery tool."""

    @property
    def name(self) -> str:
        return "Naabu"

    @property
    def binary_name(self) -> str:
        return "naabu"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [self.binary_name, "-host", target, "-json", "-silent"]

        port_range = options.get("port_range", "top100")
        if port_range == "top100":
            args.extend(["-top-ports", "100"])
        elif port_range == "top1000":
            args.extend(["-top-ports", "1000"])
        elif port_range == "1-65535":
            args.extend(["-p", "-"])
        elif isinstance(port_range, str):
            args.extend(["-p", port_range])

        if output_path:
            json_path = output_path.with_suffix(".json")
            args.extend(["-o", str(json_path)])

        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        return []

    def parse_ports(self, output_content: str) -> List[PortResult]:
        """Extract open ports from Naabu JSON lines."""
        ports: List[PortResult] = []
        for line in output_content.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                port_num = int(data.get("port", 0))
                proto = data.get("protocol", "tcp")
                if port_num > 0:
                    ports.append(PortResult(
                        port=port_num,
                        protocol=proto,
                        state=PortState.OPEN,
                        discovery_source="Naabu"
                    ))
            except Exception:
                continue
        return ports

