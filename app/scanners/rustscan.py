"""RustScan tool adapter for ultra-fast port discovery."""

from __future__ import annotations

import asyncio
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

    TOP_100_PORTS = (
        "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,"
        "139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,"
        "646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,"
        "2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,"
        "5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,"
        "10000,32768,49152,49153,49154,49155,49156,49157"
    )

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        # Use --scripts none so RustScan exits cleanly without attempting to invoke Nmap itself
        port_range = options.get("port_range", "top1000")
        batch_size = "100" if port_range == "top100" else "250"
        args = [
            self.binary_name,
            "-a", target,
            "--batch-size", batch_size,
            "--timeout", "1000" if port_range == "top100" else "1200",
            "--scripts", "none",
            "--no-config",
            "--no-banner",
            "--accessible",
        ]

        if port_range == "top100":
            args.extend(["-p", self.TOP_100_PORTS])
        elif port_range == "top1000":
            args.append("--top")
        elif port_range == "1-65535":
            args.extend(["-r", "1-65535"])
        elif isinstance(port_range, str) and port_range:
            if "," in port_range:
                args.extend(["-p", port_range])
            else:
                args.extend(["-r", port_range])

        return args

    async def scan_ports(
        self,
        scan_id: str,
        target: str,
        options: Dict[str, Any],
        evidence_dir: Optional[Path] = None,
        timeout_seconds: int = 90
    ) -> List[PortResult]:
        """Execute RustScan binary cleanly and parse discovered open TCP ports."""
        output_file = evidence_dir / "rustscan_output.raw" if evidence_dir else None
        args = self.build_command(target, options, output_path=output_file)

        res = await self.task_manager.execute_tool(
            scan_id=scan_id,
            tool_name=self.name,
            args=args,
            timeout_seconds=timeout_seconds
        )

        raw_output = f"{res.stdout}\n{res.stderr}".strip()
        if output_file:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            output_file.write_text(raw_output, encoding="utf-8", errors="replace")

        return self.parse_ports(raw_output)

    @staticmethod
    async def fast_socket_discovery(target: str, ports: Optional[List[int]] = None, timeout: float = 1.2) -> List[PortResult]:
        """Built-in fast asynchronous TCP port discovery (fallback when RustScan binary unavailable)."""
        if ports is None:
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000,
                8080, 8443, 8888, 9000, 9200, 27017
            ]

        open_ports: List[PortResult] = []
        sem = asyncio.Semaphore(50)

        async def probe(port: int):
            async with sem:
                try:
                    conn = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(PortResult(
                        port=port,
                        protocol="tcp",
                        state=PortState.OPEN,
                        discovery_source="RustScan-SocketFallback",
                        source_tools=["RustScan-SocketFallback"]
                    ))
                except Exception:
                    pass

        await asyncio.gather(*(probe(p) for p in ports))
        return sorted(open_ports, key=lambda x: x.port)

    def parse_ports(self, output_content: str) -> List[PortResult]:
        """Extract open ports from RustScan output (e.g. 'Open 127.0.0.1:80' or '[80, 443]')."""
        seen: set[int] = set()
        ports: List[PortResult] = []

        # Pattern 1: Open target:port lines
        for line in output_content.splitlines():
            match = re.search(r"Open\s+[^:\s]+:(\d+)", line, re.IGNORECASE)
            if match:
                p_num = int(match.group(1))
                if p_num not in seen:
                    seen.add(p_num)
                    ports.append(PortResult(
                        port=p_num,
                        protocol="tcp",
                        state=PortState.OPEN,
                        discovery_source="RustScan",
                        source_tools=["RustScan"]
                    ))

        # Pattern 2: [80, 443, 8080] summary array
        array_match = re.search(r"\[([0-9,\s]+)\]", output_content)
        if array_match:
            for p_str in array_match.group(1).split(","):
                p_str = p_str.strip()
                if p_str.isdigit():
                    p_num = int(p_str)
                    if p_num not in seen:
                        seen.add(p_num)
                        ports.append(PortResult(
                            port=p_num,
                            protocol="tcp",
                            state=PortState.OPEN,
                            discovery_source="RustScan",
                            source_tools=["RustScan"]
                        ))

        return sorted(ports, key=lambda x: x.port)

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        """Parse native scanner output into a list of normalized findings."""
        return []
