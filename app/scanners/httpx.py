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
        import shutil
        if shutil.which("httpx"):
            return "httpx"
        if shutil.which("httpx-toolkit"):
            return "httpx-toolkit"
        return "httpx"

    @property
    def is_available(self) -> bool:
        import shutil
        return shutil.which("httpx") is not None or shutil.which("httpx-toolkit") is not None

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [
            self.binary_name,
            "-u", target,
            "-no-stdin",
            "-timeout", "5",
            "-title",
            "-tech-detect",
            "-status-code",
            "-server",
            "-location",
            "-json",
            "-silent"
        ]

        if output_path:
            json_path = output_path.with_suffix(".jsonl")
            args.extend(["-o", str(json_path)])

        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        return []

    @staticmethod
    def build_candidate_urls(target: str, candidate_ports: Optional[List[int]] = None) -> List[str]:
        """Build explicit HTTP/HTTPS target URLs from discovered ports."""
        if target.startswith("http://") or target.startswith("https://"):
            return [target]

        ports = candidate_ports or [80, 443]
        urls: List[str] = []
        for p in ports:
            if p in (80, 8000, 8080, 8888, 3000, 5000, 9000):
                urls.append(f"http://{target}:{p}")
            elif p in (443, 8443):
                urls.append(f"https://{target}:{p}")
        return urls or [f"http://{target}:80", f"https://{target}:443"]

    async def probe(
        self,
        scan_id: str,
        target: str,
        options: Dict[str, Any],
        evidence_dir: Optional[Path] = None,
        candidate_ports: Optional[List[int]] = None
    ) -> List[ServiceResult]:
        """Execute httpx probe across discovered web ports and parse web service info."""
        output_file = None
        targets_file = None
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            output_file = evidence_dir / "httpx_output.jsonl"
            targets_file = evidence_dir / "httpx_targets.txt"

        urls = self.build_candidate_urls(target, candidate_ports)
        if targets_file:
            targets_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
            args = [
                self.binary_name,
                "-l", str(targets_file),
                "-no-stdin",
                "-timeout", "5",
                "-title",
                "-tech-detect",
                "-status-code",
                "-server",
                "-location",
                "-json",
                "-silent",
                "-o", str(output_file),
            ]
        else:
            args = self.build_command(",".join(urls), options, output_path=output_file)

        res = await self.task_manager.execute_tool(
            scan_id=scan_id,
            tool_name=self.name,
            args=args,
            timeout_seconds=min(options.get("timeout_seconds", 180), 60)
        )

        content = res.stdout
        if output_file and output_file.exists():
            try:
                content = output_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        elif output_file:
            output_file.write_text(content or "", encoding="utf-8", errors="replace")

        results: List[ServiceResult] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                scheme = data.get("scheme", "http")
                port = int(data.get("port", 80 if scheme == "http" else 443))
                techs = data.get("tech", []) or []
                title = (data.get("title") or "").strip()
                server = (data.get("webserver") or "").strip()
                status_code = data.get("status_code")
                location = (data.get("location") or "").strip()

                banner_parts = []
                if server:
                    banner_parts.append(server)
                if status_code:
                    banner_parts.append(f"HTTP {status_code}")
                if location:
                    banner_parts.append(f"-> {location}")
                if title:
                    banner_parts.append(f"Title: {title[:45]}")

                banner = " | ".join(banner_parts) if banner_parts else None

                results.append(ServiceResult(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service_name=scheme if scheme in ("http", "https") else ("https" if port in (443, 8443) else "http"),
                    service_version=server or None,
                    banner=banner,
                    technologies=techs,
                    source_tool="httpx",
                    source_tools=["httpx"]
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
                            banner_parts.append(server)
                        if resp.status_code:
                            banner_parts.append(f"HTTP {resp.status_code}")
                        if location:
                            banner_parts.append(f"-> {location}")
                        if title:
                            banner_parts.append(f"Title: {title[:45]}")

                        banner = " | ".join(banner_parts) if banner_parts else f"HTTP {resp.status_code}"

                        results.append(ServiceResult(
                            port=port,
                            protocol="tcp",
                            state="open",
                            service_name="http" if scheme == "http" else "https",
                            service_version=server or None,
                            banner=banner,
                            technologies=techs,
                            source_tool="httpx-PythonFallback",
                            source_tools=["httpx-PythonFallback"]
                        ))
                        break
                    except Exception:
                        continue

        return results
