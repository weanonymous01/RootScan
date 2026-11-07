"""SQLite repository layer with WAL mode for persistent scan data."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional

from app.database.models import FindingRecord, SCHEMA_SQL, ScanRecord, ServiceRecord


class DatabaseRepository:
    """Thread-safe SQLite database manager for RootScan."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for SQLite database connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database tables and schema."""
        with self._get_connection() as conn:
            conn.executescript(SCHEMA_SQL)

    # Scans Operations
    def create_scan(self, scan: ScanRecord) -> None:
        """Insert a new scan record."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, target, target_type, profile, status, 
                    start_time, created_at, ai_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.scan_id, scan.target, scan.target_type, scan.profile,
                    scan.status, scan.start_time, scan.created_at, scan.ai_status
                )
            )

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        end_time: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        finding_count: Optional[int] = None,
        ai_status: Optional[str] = None
    ) -> None:
        """Update status and timestamps for a scan."""
        updates = ["status = ?"]
        params: List[Any] = [status]

        if end_time is not None:
            updates.append("end_time = ?")
            params.append(end_time)
        if duration_seconds is not None:
            updates.append("duration_seconds = ?")
            params.append(duration_seconds)
        if finding_count is not None:
            updates.append("finding_count = ?")
            params.append(finding_count)
        if ai_status is not None:
            updates.append("ai_status = ?")
            params.append(ai_status)

        params.append(scan_id)
        sql = f"UPDATE scans SET {', '.join(updates)} WHERE scan_id = ?"

        with self._get_connection() as conn:
            conn.execute(sql, params)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a scan record by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve scans ordered by start_time descending."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scans ORDER BY start_time DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
            return [dict(row) for row in cursor.fetchall()]

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record (cascades to related tables)."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return cursor.rowcount > 0

    # Targets Operations
    def add_target(
        self,
        scan_id: str,
        raw_input: str,
        normalized_target: str,
        target_type: str,
        is_private: bool,
        resolved_ips: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO targets (
                    scan_id, raw_input, normalized_target, target_type, 
                    is_private, resolved_ips, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, raw_input, normalized_target, target_type,
                    1 if is_private else 0, json.dumps(resolved_ips),
                    json.dumps(metadata or {})
                )
            )

    # Services Operations
    def add_service(self, service: ServiceRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO services (
                    scan_id, port, protocol, state, service_name, 
                    service_version, banner, tech_stack
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    service.scan_id, service.port, service.protocol, service.state,
                    service.service_name, service.service_version,
                    service.banner, service.tech_stack
                )
            )

    def get_services(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM services WHERE scan_id = ? ORDER BY port ASC", (scan_id,))
            return [dict(row) for row in cursor.fetchall()]

    # Findings Operations
    def add_finding(self, finding: FindingRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO findings (
                    scan_id, title, cve_id, severity, confidence, 
                    affected_component, observed_version, source_tool, 
                    evidence_text, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.scan_id, finding.title, finding.cve_id, finding.severity,
                    finding.confidence, finding.affected_component, finding.observed_version,
                    finding.source_tool, finding.evidence_text, finding.remediation
                )
            )

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
            return [dict(row) for row in cursor.fetchall()]

    # AI Analysis Operations
    def save_ai_analysis(
        self,
        scan_id: str,
        model: str,
        executive_summary: str,
        attack_surface_analysis: str,
        vulnerability_explanation: str,
        exploit_intelligence: str,
        attack_path_analysis: str,
        recommendations: str,
        full_analysis_json: str
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ai_analyses (
                    scan_id, model, executive_summary, attack_surface_analysis,
                    vulnerability_explanation, exploit_intelligence,
                    attack_path_analysis, recommendations, full_analysis_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, model, executive_summary, attack_surface_analysis,
                    vulnerability_explanation, exploit_intelligence,
                    attack_path_analysis, recommendations, full_analysis_json,
                    datetime.utcnow().isoformat()
                )
            )

    def get_ai_analysis(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM ai_analyses WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # AI Conversation Operations (Multi-turn chat per scan)
    def add_ai_message(self, conversation_id: str, scan_id: str, role: str, content: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO ai_conversations (
                    conversation_id, scan_id, role, content, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (conversation_id, scan_id, role, content, datetime.utcnow().isoformat())
            )

    def get_ai_conversation(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT role, content, created_at FROM ai_conversations WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,)
            )
            return [dict(row) for row in cursor.fetchall()]

    # Tool Registry Operations
    def update_tool_status(self, tool_name: str, binary_path: Optional[str], is_installed: bool, version: Optional[str]) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tool_registry (
                    tool_name, binary_path, is_installed, version, last_verified
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    tool_name, binary_path, 1 if is_installed else 0,
                    version, datetime.utcnow().isoformat()
                )
            )

    def get_registered_tools(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM tool_registry ORDER BY tool_name ASC")
            return [dict(row) for row in cursor.fetchall()]

