"""WhatWeb tool adapter for web technology fingerprinting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.reports.schemas import NormalizedFinding, ServiceResult
from app.scanners.base import BaseScannerAdapter


class WhatWebAdapter(BaseScannerAdapter):
    """Adapter for WhatWeb technology identifier."""

    @property
    def name(self) -> str:
        return "WhatWeb"

    @property
    def binary_name(self) -> str:
        return "whatweb"

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [self.binary_name, "--color=never", "-a", "1"]

        if output_path:
            json_path = output_path.with_suffix(".json")
            args.append(f"--log-json={json_path}")

        args.append(target)
        return args

    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        return []

    def parse_services(self, json_content: str) -> List[ServiceResult]:
        """Extract discovered technologies and HTTP servers from WhatWeb JSON output."""
        services: List[ServiceResult] = []
        if not json_content or not json_content.strip():
            return services

        try:
            entries = json.loads(json_content)
            if isinstance(entries, dict):
                entries = [entries]
        except Exception:
            return services

        for entry in entries:
            target_url = entry.get("target", "")
            port = 443 if target_url.startswith("https") else 80
            plugins = entry.get("plugins", {})
            
            tech_list: List[str] = []
            server_version = None

            for plugin_name, plugin_info in plugins.items():
                version = None
                if isinstance(plugin_info, dict):
                    version_list = plugin_info.get("version", [])
                    if version_list and isinstance(version_list, list):
                        version = version_list[0]
                
                tech_str = f"{plugin_name} {version}".strip() if version else plugin_name
                tech_list.append(tech_str)

                if plugin_name.lower() in ("httpserver", "apache", "nginx", "iis", "caddy"):
                    server_version = tech_str

            services.append(ServiceResult(
                port=port,
                protocol="tcp",
                state="open",
                service_name="https" if port == 443 else "http",
                service_version=server_version,
                banner=", ".join(tech_list[:5]),
                technologies=tech_list,
                source_tool="WhatWeb"
            ))

        return services

