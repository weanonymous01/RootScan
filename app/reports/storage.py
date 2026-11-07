"""Persistent scan directory and evidence storage management."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import secrets
from typing import Any, Dict, Optional

from app.core.configuration import get_config


def generate_scan_id() -> str:
    """
    Generate unique scan identifier matching SCN-YYYYMMDD-XXXXX format.
    Example: SCN-20261107-A8F29
    """
    date_str = datetime.utcnow().strftime("%Y%m%d")
    random_hex = secrets.token_hex(3).upper()[:5]
    return f"SCN-{date_str}-{random_hex}"


class ReportStorage:
    """Manages file storage for scan stages, raw evidence, and reports."""

    def __init__(self, base_scans_dir: Optional[Path] = None):
        config = get_config()
        self.scans_dir = base_scans_dir or config.scans_dir
        self.scans_dir.mkdir(parents=True, exist_ok=True)

    def get_scan_dir(self, scan_id: str) -> Path:
        """Return and ensure directory path for a specific scan."""
        path = self.scans_dir / scan_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_evidence_dir(self, scan_id: str) -> Path:
        """Return and ensure directory path for raw scanner evidence."""
        path = self.get_scan_dir(scan_id) / "evidence"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_stage_json(self, scan_id: str, stage_file: str, data: Any) -> Path:
        """Serialize data to JSON within the scan's directory."""
        scan_dir = self.get_scan_dir(scan_id)
        file_path = scan_dir / stage_file
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return file_path

    def load_stage_json(self, scan_id: str, stage_file: str) -> Optional[Dict[str, Any]]:
        """Load serialized JSON from scan directory if present."""
        file_path = self.get_scan_dir(scan_id) / stage_file
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def save_markdown_report(self, scan_id: str, content: str) -> Path:
        """Save human-readable Markdown final report."""
        scan_dir = self.get_scan_dir(scan_id)
        file_path = scan_dir / "final_report.md"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return file_path

    def save_html_report(self, scan_id: str, content: str) -> Path:
        """Save self-contained modern HTML report."""
        scan_dir = self.get_scan_dir(scan_id)
        file_path = scan_dir / "final_report.html"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return file_path

