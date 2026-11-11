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

    QUICK_TEMPLATE_CANDIDATES = (
        "ssl/",
        "http/misconfiguration/http-missing-security-headers.yaml",
        "http/misconfiguration/directory-listing-no-host-header.yaml",
        "http/misconfiguration/server-status.yaml",
        "http/misconfiguration/apache/",
        "http/misconfiguration/nginx/",
        "http/exposures/configs/git-config.yaml",
        "http/exposures/configs/phpinfo-files.yaml",
        "http/exposures/backups/backup-directory-listing.yaml",
    )

    @classmethod
    def _quick_templates(cls) -> List[str]:
        """Select high-signal fast templates present on disk, falling back cleanly."""
        tpl_root = Path.home() / "nuclei-templates"
        if tpl_root.exists():
            selected = [t for t in cls.QUICK_TEMPLATE_CANDIDATES if (tpl_root / t.rstrip("/")).exists()]
            if selected:
                return selected
        return ["ssl/", "http/misconfiguration/http-missing-security-headers.yaml"]

    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        args = [
            self.binary_name,
        ]

        targets_list = options.get("_target_list_file")
        if targets_list:
            args.extend(["-l", str(targets_list)])
        else:
            args.extend(["-u", target])

        profile_name = options.get("_profile_name", "quick")
        args.extend([
            "-ni",            # Disable Interactsh OAST initialization to prevent stalls
            "-no-stdin",
            "-duc",
            "-no-color",
            "-jsonl",
            "-silent",
            "-timeout", "4",
            "-retries", "0",
            "-c", "15" if profile_name == "quick" else "25",
            "-mhe", "250",    # Prevent premature skip when single host drops burst probes
        ])

        if profile_name == "quick":
            args.extend(["-t", ",".join(self._quick_templates())])
            args.extend(["-severity", "critical,high,medium,low,info"])
        else:
            severities = options.get("nuclei_severity", ["critical", "high", "medium", "low"])
            if severities:
                args.extend(["-severity", ",".join(severities)])

        # Cap rate-limit safely to prevent connection drops on single targets
        cap = 50 if profile_name == "quick" else 100
        rate_limit = min(int(options.get("rate_limit", cap)), cap)
        args.extend(["-rate-limit", str(rate_limit)])

        if output_path:
            jsonl_path = output_path.with_suffix(".jsonl")
            args.extend(["-o", str(jsonl_path)])

        return args

    async def scan_targets(
        self,
        scan_id: str,
        targets: List[str],
        options: Dict[str, Any],
        evidence_dir: Optional[Path] = None,
        timeout_seconds: int = 120
    ):
        """Execute Nuclei across one or more target URLs cleanly and parse findings."""
        opts = dict(options)
        if evidence_dir and len(targets) > 1:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            targets_file = evidence_dir / "nuclei_targets.txt"
            targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
            opts["_target_list_file"] = str(targets_file)
            primary_target = targets[0]
        else:
            primary_target = targets[0]

        return await self.execute(
            scan_id=scan_id,
            target=primary_target,
            options=opts,
            evidence_dir=evidence_dir,
            timeout_seconds=timeout_seconds
        )

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
