"""Base adapter interface for external security scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional

from app.core.task_manager import TaskManager, ToolExecutionResult
from app.reports.schemas import NormalizedFinding


class BaseScannerAdapter(ABC):
    """Abstract base class for all security tool adapters."""

    def __init__(self, task_manager: Optional[TaskManager] = None):
        self.task_manager = task_manager or TaskManager()

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable tool name (e.g. 'Nmap')."""
        pass

    @property
    @abstractmethod
    def binary_name(self) -> str:
        """Name of the binary executable (e.g. 'nmap')."""
        pass

    @property
    def is_available(self) -> bool:
        """Check whether the tool binary is present in system PATH."""
        return shutil.which(self.binary_name) is not None

    async def get_version(self) -> str:
        """Detect and return tool version string."""
        if not self.is_available:
            return "Not Installed"
        try:
            res = await self.task_manager.execute_tool(
                scan_id="VERSION_CHECK",
                tool_name=self.name,
                args=[self.binary_name, "--version"],
                timeout_seconds=10
            )
            lines = [l.strip() for l in (res.stdout or res.stderr).splitlines() if l.strip()]
            for l in lines:
                if "version" in l.lower() or "v1." in l.lower() or "v2." in l.lower() or "v3." in l.lower():
                    return l
            return lines[0] if lines else "Installed"
        except Exception:
            return "Unknown"

    @abstractmethod
    def build_command(self, target: str, options: Dict[str, Any], output_path: Optional[Path] = None) -> List[str]:
        """Construct safe command arguments array without shell interpolation."""
        pass

    @abstractmethod
    async def parse_output(self, output_content: str, evidence_path: Optional[Path] = None) -> List[NormalizedFinding]:
        """Parse native scanner output into a list of normalized findings."""
        pass

    async def execute(
        self,
        scan_id: str,
        target: str,
        options: Dict[str, Any],
        evidence_dir: Optional[Path] = None,
        timeout_seconds: int = 300
    ) -> tuple[ToolExecutionResult, List[NormalizedFinding]]:
        """
        Execute tool through TaskManager, save raw evidence, and return parsed findings.
        """
        output_file = None
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            output_file = evidence_dir / f"{self.binary_name}_output.raw"

        args = self.build_command(target, options, output_path=output_file)
        result = await self.task_manager.execute_tool(
            scan_id=scan_id,
            tool_name=self.name,
            args=args,
            timeout_seconds=timeout_seconds
        )

        # Save raw evidence if directory provided
        if output_file and not output_file.exists():
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)

        content_to_parse = result.stdout
        if output_file and output_file.exists():
            try:
                content_to_parse = output_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

        findings = await self.parse_output(content_to_parse, evidence_path=output_file)
        return result, findings

