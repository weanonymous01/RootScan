"""httpx tool adapter for HTTP service probing and tech fingerprinting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.reports.schemas import NormalizedFinding, ServiceResult
from app.scanners.base import BaseScannerAdapter


class HttpxAdapter(BaseScannerAdapter):
    """Adapter for ProjectDiscovery httpx probe."""

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def binary_name(self) -> str:
        return "httpx"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [
            self.binary_name,
            "-u", target,
            "-title",
            "-tech-detect",
            "-status-code",
            "-server",
            "-json",
            "-silent"
        ]

        if output_path:
            json_path = output_path.with_suffix(".jsonl")
            args.extend(["-o", str(json_path)])

        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        # httpx primarily returns service and technology information
        return []

    async def probe(self, scan_id: str, target: str, options: Dict[str, Any], evidence_dir: Optional[Path] = None) -> List[ServiceResult]:
        """Execute httpx probe and parse discovered web services."""
        output_file = None
        if evidence_dir:
            output_file = evidence_dir / "httpx.jsonl"

        args = self.build_command(target, options, output_path=output_file)
        res = await self.task_manager.execute_tool(
            scan_id=scan_id,
            tool_name=self.name,
            args=args,
            timeout_seconds=options.get("timeout_seconds", 180)
        )

        content = res.stdout
        if output_file and output_file.exists():
            try:
                content = output_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

        results: List[ServiceResult] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                port = int(data.get("port", 80 if data.get("scheme") == "http" else 443))
                techs = data.get("tech", []) or []
                title = data.get("title", "")
                server = data.get("webserver", "")
                banner = f"{server} | Title: {title}".strip(" |")

                results.append(ServiceResult(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service_name="http" if port in (80, 8080) else "https",
                    service_version=server or None,
                    banner=banner or None,
                    technologies=techs,
                    source_tool="httpx"
                ))
            except Exception:
                continue

        return results

