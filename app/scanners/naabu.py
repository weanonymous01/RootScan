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
        args = [
            self.binary_name,
            "-host", target,
            "-json",
            "-silent",
            "-no-stdin",
            "-duc",
            "-retries", "1",
            "-warm-up-time", "0",
            "-timeout", "500ms",
            "-rate", "500",
            "-c", "25",
        ]

        port_range = options.get("port_range", "top100")
        if port_range == "top100":
            args.extend(["-top-ports", "100"])
        elif port_range == "top1000":
            args.extend(["-top-ports", "1000"])
        elif port_range == "1-65535":
            args.extend(["-p", "-"])
        elif isinstance(port_range, str) and port_range:
            args.extend(["-p", port_range])

        if output_path:
            json_path = output_path.with_suffix(".json")
            args.extend(["-o", str(json_path)])

        return args

    async def scan_ports(
        self,
        scan_id: str,
        target: str,
        options: Dict[str, Any],
        evidence_dir: Optional[Path] = None,
        timeout_seconds: int = 60
    ) -> List[PortResult]:
        """Execute Naabu and return discovered open ports attributed to Naabu."""
        output_file = evidence_dir / "naabu_output.json" if evidence_dir else None
        args = self.build_command(target, options, output_path=output_file)

        res = await self.task_manager.execute_tool(
            scan_id=scan_id,
            tool_name=self.name,
            args=args,
            timeout_seconds=timeout_seconds
        )

        content = res.stdout
        if output_file and output_file.exists():
            try:
                content = output_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        elif output_file:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content or "", encoding="utf-8", errors="replace")

        return self.parse_ports(content)

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        return []

    def parse_ports(self, output_content: str) -> List[PortResult]:
        """Extract open ports from Naabu JSON lines."""
        seen: set[tuple[int, str]] = set()
        ports: List[PortResult] = []
        for line in output_content.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                port_num = int(data.get("port", 0))
                proto = data.get("protocol", "tcp")
                if port_num > 0 and (port_num, proto) not in seen:
                    seen.add((port_num, proto))
                    ports.append(PortResult(
                        port=port_num,
                        protocol=proto,
                        state=PortState.OPEN,
                        discovery_source="Naabu",
                        source_tools=["Naabu"]
                    ))
            except Exception:
                continue
        return sorted(ports, key=lambda x: x.port)
