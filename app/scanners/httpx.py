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

    @staticmethod
    async def python_fallback_probe(target: str, ports: List[int], timeout: float = 4.0) -> List[ServiceResult]:
        """Built-in pure-Python HTTP probe using httpx library when binary is not in PATH."""
        import httpx as py_httpx
        import re

        results: List[ServiceResult] = []
        client_options = {"verify": False, "timeout": timeout, "follow_redirects": False}

        async with py_httpx.AsyncClient(**client_options) as client:
            for port in ports:
                schemes = ["http"] if port in (80, 8080, 8000, 8888) else (["https"] if port in (443, 8443) else ["http", "https"])
                for scheme in schemes:
                    url = f"{scheme}://{target}:{port}/"
                    try:
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 RootScan/1.0"})
                        server = resp.headers.get("server", "").strip()
                        powered_by = resp.headers.get("x-powered-by", "").strip()
                        location = resp.headers.get("location", "").strip()

                        title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                        title = title_match.group(1).strip() if title_match else ""

                        techs: List[str] = []
                        if server:
                            techs.append(server)
                        if powered_by:
                            techs.append(f"X-Powered-By:{powered_by}")

                        banner_parts = []
                        if server:
                            banner_parts.append(f"Server: {server}")
                        if resp.status_code:
                            banner_parts.append(f"HTTP {resp.status_code}")
                        if location:
                            banner_parts.append(f"Redirect: {location}")
                        if title:
                            banner_parts.append(f"Title: {title[:40]}")

                        banner = " | ".join(banner_parts) if banner_parts else f"HTTP {resp.status_code}"

                        results.append(ServiceResult(
                            port=port,
                            protocol="tcp",
                            state="open",
                            service_name="http" if scheme == "http" else "https",
                            service_version=server or None,
                            banner=banner,
                            technologies=techs,
                            source_tool="httpx-engine"
                        ))
                        break
                    except Exception:
                        continue

        return results


