"""Database models and SQLite schema definitions for RootScan."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,          -- pending, running, completed, interrupted, failed
    start_time TEXT NOT NULL,
    end_time TEXT,
    duration_seconds REAL,
    finding_count INTEGER DEFAULT 0,
    ai_status TEXT DEFAULT 'pending', -- pending, running, completed, skipped, failed
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    raw_input TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    is_private INTEGER DEFAULT 0,
    resolved_ips TEXT,             -- JSON array
    metadata TEXT,                 -- JSON object (ASN, RDAP, Geolocation)
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_stages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    stage_name TEXT NOT NULL,
    status TEXT NOT NULL,          -- pending, running, completed, skipped, failed
    start_time TEXT,
    end_time TEXT,
    duration_seconds REAL,
    stage_order INTEGER NOT NULL,
    error_message TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    stage_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    command TEXT NOT NULL,
    exit_code INTEGER,
    start_time TEXT,
    end_time TEXT,
    duration_seconds REAL,
    timed_out INTEGER DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    os_indicator TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,        -- tcp, udp
    state TEXT NOT NULL,           -- open, filtered, closed
    service_name TEXT,
    service_version TEXT,
    banner TEXT,
    tech_stack TEXT,               -- JSON array
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    cve_id TEXT,
    severity TEXT NOT NULL,        -- critical, high, medium, low, info
    confidence TEXT NOT NULL,      -- confirmed, suspected, hypothesis
    affected_component TEXT,
    observed_version TEXT,
    source_tool TEXT NOT NULL,
    evidence_text TEXT,
    remediation TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_type TEXT NOT NULL,        -- xml, json, jsonl, txt
    file_size_bytes INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    model TEXT NOT NULL,
    executive_summary TEXT,
    attack_surface_analysis TEXT,
    vulnerability_explanation TEXT,
    exploit_intelligence TEXT,
    attack_path_analysis TEXT,
    recommendations TEXT,
    full_analysis_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    role TEXT NOT NULL,            -- user, assistant, system
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tool_registry (
    tool_name TEXT PRIMARY KEY,
    binary_path TEXT,
    is_installed INTEGER DEFAULT 0,
    version TEXT,
    last_verified TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@dataclass
class ScanRecord:
    scan_id: str
    target: str
    target_type: str
    profile: str
    status: str
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    finding_count: int = 0
    ai_status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ServiceRecord:
    scan_id: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    tech_stack: Optional[str] = None


@dataclass
class FindingRecord:
    scan_id: str
    title: str
    severity: str
    confidence: str
    source_tool: str
    cve_id: Optional[str] = None
    affected_component: Optional[str] = None
    observed_version: Optional[str] = None
    evidence_text: Optional[str] = None
    remediation: Optional[str] = None

