"""RustScan-inspired Terminal User Interface (TUI) for RootScan."""

from __future__ import annotations

import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.markup import escape as rich_escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    Markdown,
    RadioButton,
    RadioSet,
    Static,
    Switch,
)

from app.ai.nim_client import NimClient
from app.core.configuration import get_config
from app.core.event_bus import EventType, ScanEvent, get_event_bus
from app.core.orchestrator import ScanOrchestrator
from app.database.repository import DatabaseRepository
from app.reports.storage import ReportStorage
from app.scanners.httpx import HttpxAdapter
from app.scanners.naabu import NaabuAdapter
from app.scanners.nikto import NiktoAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter
from app.scanners.rustscan import RustScanAdapter
from app.scanners.whatweb import WhatWebAdapter


# ==============================================================================
# RustScan-Inspired Minimal Hacker Terminal Styling
# ==============================================================================

RUSTSCAN_CSS = """
Screen {
    background: #080c10;
    color: #c9d1d9;
    font-family: monospace;
}

Header {
    background: #0d1117;
    color: #00ff66;
    text-style: bold;
    dock: top;
    height: 1;
    border-bottom: solid #21262d;
}

Footer {
    background: #0d1117;
    color: #8b949e;
    dock: bottom;
    height: 1;
    border-top: solid #21262d;
}

#terminal-container {
    padding: 0 1;
}

.ascii-banner {
    color: #00e5ff;
    text-style: bold;
    margin-bottom: 0;
    padding: 0;
}

.terminal-meta-box {
    background: #0d1117;
    border: solid #21262d;
    padding: 0 1;
    margin-bottom: 1;
}

.terminal-line {
    color: #c9d1d9;
}

.term-tag-success {
    color: #00ff66;
    text-style: bold;
}

.term-tag-info {
    color: #00e5ff;
    text-style: bold;
}

.term-tag-warn {
    color: #ffd700;
    text-style: bold;
}

.term-tag-err {
    color: #ff3366;
    text-style: bold;
}

/* Monospace Flat Terminal Navigation */
.nav-bar {
    background: #0d1117;
    border-top: solid #21262d;
    border-bottom: solid #21262d;
    height: 3;
    padding: 0 1;
    margin-bottom: 1;
    align: center middle;
}

Button {
    background: #161b22;
    color: #c9d1d9;
    border: none;
    margin: 0 1;
    min-width: 14;
    height: 1;
    padding: 0 1;
    text-style: bold;
}

Button:hover {
    background: #00ff66;
    color: #080c10;
}

Button.-primary {
    background: #00e5ff;
    color: #080c10;
}

Button.-primary:hover {
    background: #00ff66;
    color: #080c10;
}

Button.-danger {
    background: #ff3366;
    color: #ffffff;
}

Button.-danger:hover {
    background: #ff6688;
    color: #ffffff;
}

Input {
    background: #0d1117;
    border: solid #30363d;
    color: #00ff66;
    padding: 0 1;
    margin: 0;
    height: 3;
}

Input:focus {
    border: solid #00e5ff;
    color: #ffffff;
}

DataTable {
    background: #080c10;
    border: solid #21262d;
    color: #c9d1d9;
    height: auto;
    max-height: 16;
}

DataTable > .datatable--header {
    background: #161b22;
    color: #00e5ff;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #21262d;
    color: #00ff66;
}

Log {
    background: #05070a;
    border: solid #21262d;
    color: #c9d1d9;
    min-height: 16;
    max-height: 24;
}

.live-header-bar {
    background: #0d1117;
    border: solid #21262d;
    padding: 0 1;
    margin-bottom: 1;
    height: 3;
}

.prompt-prefix {
    color: #00ff66;
    text-style: bold;
}
"""

ASCII_LOGO = """[bold cyan]
  ____             _   ____                  
 |  _ \ ___   ___ | |_/ ___|  ___ __ _ _ __  
 | |_) / _ \ / _ \| __\___ \ / __/ _` | '_ \ 
 |  _ < (_) | (_) | |_ ___) | (_| (_| | | | |
 |_| \_\___/ \___/ \__|____/ \___\__,_|_| |_|
[/bold cyan]"""


# ==============================================================================
# Helper Navigation Bar Component
# ==============================================================================

class TerminalNavBar(Static):
    """Compact CLI navigation shortcut bar."""

    def compose(self) -> ComposeResult:
        with Horizontal(classes="nav-bar"):
            yield Button("[1] New Scan", id="nav-new")
            yield Button("[2] History", id="nav-history")
            yield Button("[3] AI Analyst", id="nav-ai")
            yield Button("[4] Tool Health", id="nav-tools")
            yield Button("[5] Settings", id="nav-settings")
            yield Button("[Q] Quit", id="nav-quit", variant="danger")


# ==============================================================================
# Screen 1: Dashboard
# ==============================================================================

class DashboardScreen(Screen):
    """RustScan-style startup terminal dashboard."""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with ScrollableContainer(id="terminal-container"):
            yield Static(ASCII_LOGO, classes="ascii-banner")
            yield Static("[bold white]RootScan v1.0.0[/bold white] — [dim]Automated Security Assessment & Pentesting Toolkit[/dim]\n")

            # System & Tool Status Block
            with Vertical(classes="terminal-meta-box"):
                yield Label("[bold green][+][/bold green] Status       : [bold white]OPERATIONAL[/bold white] [dim](Local Monolithic Engine)[/dim]")
                yield Label("[bold cyan][>][/bold cyan] AI Provider  : [bold cyan]NVIDIA NIM API[/bold cyan] [dim](model: nvidia/nemotron-3.5-lightning-30b-a3b)[/dim]", id="lbl-ai-status")
                yield Label("[bold cyan][>][/bold cyan] Security Core: [bold white]Anti-SSRF Enabled[/bold white] | RFC1918 Scope Gate Active", id="lbl-core-status")
                yield Label("[bold green][+][/bold green] Tools Ready  : Scanning PATH for Nmap, Nuclei, httpx, RustScan, Naabu...", id="lbl-tools-summary")
                yield Label("[bold green][+][/bold green] Total Scans  : [bold white]0[/bold white] stored in SQLite database", id="lbl-scan-count")

            # Navigation Bar
            yield TerminalNavBar()

            # Monospace Scans History Preview
            yield Label("[bold green][+][/bold green] [bold white]RECENT ASSESSMENTS[/bold white]")
            yield DataTable(id="tbl-recent-scans")

        yield Footer()

    async def on_mount(self) -> None:
        config = get_config()
        db = DatabaseRepository(config.database_path)

        # Scans count & recent list
        scans = db.list_scans(limit=8)
        self.query_one("#lbl-scan-count", Label).update(
            f"[bold green][+][/bold green] Total Scans  : [bold white]{len(scans)}[/bold white] recorded in SQLite repository"
        )

        table = self.query_one("#tbl-recent-scans", DataTable)
        table.add_columns("SCAN ID", "TARGET", "PROFILE", "STATUS", "FINDINGS", "AI", "TIMESTAMP")
        for s in scans:
            status_color = "green" if s["status"] == "completed" else "yellow"
            table.add_row(
                Text(s["scan_id"], style="bold cyan"),
                s["target"],
                s["profile"],
                Text(s["status"].upper(), style=f"bold {status_color}"),
                str(s["finding_count"]),
                s["ai_status"],
                s["start_time"][:19]
            )

        # Tool readiness
        adapters = [NmapAdapter(), NucleiAdapter(), HttpxAdapter(), RustScanAdapter(), NaabuAdapter(), WhatWebAdapter(), NiktoAdapter()]
        installed = [a.name for a in adapters if a.is_available]
        self.query_one("#lbl-tools-summary", Label).update(
            f"[bold green][+][/bold green] Tools Ready  : [bold green]{len(installed)}/{len(adapters)}[/bold green] [dim]({', '.join(installed) if installed else 'None installed; run install.sh'})[/dim]"
        )

        # AI check
        client = NimClient()
        if client.is_configured:
            self.query_one("#lbl-ai-status", Label).update(
                f"[bold cyan][>][/bold cyan] AI Provider  : [bold green]ONLINE[/bold green] — NVIDIA NIM ([cyan]{client.model}[/cyan])"
            )
        else:
            self.query_one("#lbl-ai-status", Label).update(
                "[bold cyan][>][/bold cyan] AI Provider  : [bold yellow]OFFLINE[/bold yellow] — Set NVIDIA_NIM_API_KEY in .env"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "nav-new":
            self.app.push_screen(NewScanScreen())
        elif btn_id == "nav-history":
            self.app.push_screen(HistoryScreen())
        elif btn_id == "nav-ai":
            self.app.push_screen(AIChatScreen())
        elif btn_id == "nav-tools":
            self.app.push_screen(ToolRegistryScreen())
        elif btn_id == "nav-settings":
            self.app.push_screen(SettingsScreen())
        elif btn_id == "nav-quit":
            self.app.exit()


# ==============================================================================
# Screen 2: New Scan
# ==============================================================================

class NewScanScreen(Screen):
    """Hacker-style assessment configuration screen."""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="terminal-container"):
            yield Static("\n[bold cyan]=== [>] CONFIGURE SECURITY ASSESSMENT ===[/bold cyan]\n")

            yield Label("[bold green][+][/bold green] Target IP Address or Hostname:")
            yield Input(placeholder="e.g. scanme.nmap.org or 45.33.32.156", id="txt-target")

            yield Label("\n[bold green][+][/bold green] Assessment Profile:")
            with RadioSet(id="radio-profile"):
                yield RadioButton("[1] Quick    — Top 100 ports, fast recon, essential checks", id="quick", value=True)
                yield RadioButton("[2] Standard — Top 1000 ports, service fingerprinting, Nuclei", id="standard")
                yield RadioButton("[3] Deep     — Full 1-65535 port spectrum, deep vulnerability templates", id="deep")

            yield Label("\n[bold yellow][*][/bold yellow] Scope Authorization:")
            with Horizontal():
                yield Switch(id="sw-private-scope")
                yield Label("  Authorize Internal / RFC 1918 Private Subnets", classes="terminal-line")

            with Horizontal(classes="nav-bar"):
                yield Button("[Enter] Launch Assessment", id="btn-submit-scan", variant="primary")
                yield Button("[Esc] Cancel", id="btn-cancel-scan")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-scan":
            self.app.pop_screen()
        elif event.button.id == "btn-submit-scan":
            target = self.query_one("#txt-target", Input).value.strip()
            if not target:
                self.notify("[!] Target cannot be empty.", severity="error")
                return

            profile_set = self.query_one("#radio-profile", RadioSet)
            profile_name = profile_set.pressed_button.id if profile_set.pressed_button else "quick"
            allow_private = self.query_one("#sw-private-scope", Switch).value

            self.app.push_screen(LiveScanScreen(target=target, profile=profile_name, allow_private=allow_private))


# ==============================================================================
# Screen 3: Live Scan (The Central RustScan Terminal Experience)
# ==============================================================================

class LiveScanScreen(Screen):
    """Real-time terminal execution view mirroring RustScan aesthetic."""

    def __init__(self, target: str, profile: str, allow_private: bool):
        super().__init__()
        self.target = target
        self.profile = profile
        self.allow_private = allow_private
        self.scan_id = "SCN-PENDING"
        self.orchestrator = ScanOrchestrator()
        self.start_time = datetime.utcnow()

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="terminal-container"):
            # Status Header Bar
            with Horizontal(classes="live-header-bar"):
                yield Label(f"[bold green][+][/bold green] TARGET: [bold white]{self.target}[/bold white]  |  PROFILE: [bold cyan]{self.profile.upper()}[/bold cyan]  |  STAGE: [bold yellow]VALIDATING[/bold yellow]", id="lbl-live-header")
                yield Button("[X] Abort Scan", id="btn-abort", variant="danger")

            yield Label("[bold green][+][/bold green] [bold white]REAL-TIME EVENT STREAM[/bold white]")
            yield Log(id="live-log")

            yield Label("\n[bold green][+][/bold green] [bold white]DISCOVERED PORTS & SERVICES[/bold white]")
            yield DataTable(id="tbl-live-services")

            with Horizontal(classes="nav-bar"):
                yield Button("[1] View Report", id="btn-view-report", variant="primary")
                yield Button("[Esc] Return to Dashboard", id="btn-back-dash")

        yield Footer()

    async def on_mount(self) -> None:
        log = self.query_one("#live-log", Log)
        log.write_line("[bold green][+][/bold green] [bold white]ROOTSCAN v1.0[/bold white]")
        log.write_line(f"[bold green][+][/bold green] Target specified: [cyan]{self.target}[/cyan]")
        log.write_line("[bold green][+][/bold green] Initiating asynchronous execution pipeline...")

        table = self.query_one("#tbl-live-services", DataTable)
        table.add_columns("PORT", "PROTO", "STATE", "SERVICE", "VERSION / BANNER")

        event_bus = get_event_bus()

        async def on_scan_event(event: ScanEvent):
            if event.event_type == EventType.STAGE_STARTED:
                self.query_one("#lbl-live-header", Label).update(
                    f"[bold green][+][/bold green] TARGET: [bold white]{self.target}[/bold white]  |  STAGE: [bold yellow]{event.stage_name.upper()}[/bold yellow]  |  ID: [cyan]{event.scan_id}[/cyan]"
                )
                log.write_line(f"[bold cyan][>][/bold cyan] Entering stage: [bold white]{event.stage_name}[/bold white] [dim]({event.message or ''})[/dim]")
            elif event.event_type == EventType.TOOL_STARTED:
                log.write_line(f"  [bold cyan][>][/bold cyan] Executing [bold cyan]{event.tool_name}[/bold cyan]...")
            elif event.event_type == EventType.TOOL_OUTPUT:
                line = event.message or ""
                # Syntax highlight ports in stream like RustScan
                if "/tcp" in line or "/udp" in line or "OPEN" in line:
                    log.write_line(f"  [bold green][+][/bold green] {line}")
                else:
                    log.write_line(f"      [dim]{line}[/dim]")
            elif event.event_type == EventType.TOOL_COMPLETED:
                log.write_line(f"  [bold green][+][/bold green] {event.tool_name} completed.")
            elif event.event_type == EventType.TOOL_FAILED:
                log.write_line(f"  [bold red][-][/bold red] {event.tool_name}: {event.message or 'exited with error'}")
            elif event.event_type == EventType.SCAN_COMPLETED:
                self.query_one("#lbl-live-header", Label).update(
                    f"[bold green][+][/bold green] TARGET: [bold white]{self.target}[/bold white]  |  STATUS: [bold green]COMPLETED[/bold green]  |  ID: [cyan]{event.scan_id}[/cyan]"
                )
                log.write_line(f"\n[bold green][+][/bold green] [bold white]Assessment completed successfully.[/bold white]")
                log.write_line(f"[bold green][+][/bold green] Reports saved to: [cyan]data/scans/{event.scan_id}/[/cyan]")

        event_bus.subscribe_all(on_scan_event)
        asyncio.create_task(self._execute())

    async def _execute(self):
        success, scan_id, report = await self.orchestrator.execute_scan(
            raw_target=self.target,
            profile_name=self.profile,
            allow_private=self.allow_private
        )
        if success and report:
            self.scan_id = scan_id
            table = self.query_one("#tbl-live-services", DataTable)
            for s in report.services:
                table.add_row(
                    Text(str(s.port), style="bold cyan"),
                    s.protocol.upper(),
                    Text(s.state.upper(), style="bold green"),
                    s.service_name or "unknown",
                    s.banner or s.service_version or "-"
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-abort":
            asyncio.create_task(self.orchestrator.cancel_scan(self.scan_id))
            self.notify("[!] Cancellation signal sent.", severity="warning")
        elif btn_id == "btn-back-dash":
            self.app.pop_screen()
        elif btn_id == "btn-view-report":
            if self.scan_id and self.scan_id != "SCN-PENDING":
                self.app.push_screen(ReportViewerScreen(self.scan_id))
            else:
                self.notify("Scan still in progress...", severity="information")


# ==============================================================================
# Screen 4: Scan History
# ==============================================================================

class HistoryScreen(Screen):
    """Terminal assessment history viewer."""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="terminal-container"):
            yield Static("\n[bold cyan]=== [>] ASSESSMENT HISTORY LOG ===[/bold cyan]\n")
            yield DataTable(id="tbl-history")
            with Horizontal(classes="nav-bar"):
                yield Button("[Enter] View Selected Report", id="btn-open-report", variant="primary")
                yield Button("[A] Ask AI About Scan", id="btn-ask-ai")
                yield Button("[Esc] Back", id="btn-back")

        yield Footer()

    async def on_mount(self) -> None:
        config = get_config()
        db = DatabaseRepository(config.database_path)
        scans = db.list_scans(limit=100)

        table = self.query_one("#tbl-history", DataTable)
        table.cursor_type = "row"
        table.add_columns("SCAN ID", "TARGET", "PROFILE", "STATUS", "FINDINGS", "AI STATUS", "DATE")
        for s in scans:
            status_color = "green" if s["status"] == "completed" else "yellow"
            table.add_row(
                Text(s["scan_id"], style="bold cyan"),
                s["target"],
                s["profile"],
                Text(s["status"].upper(), style=f"bold {status_color}"),
                str(s["finding_count"]),
                s["ai_status"],
                s["start_time"][:19],
                key=s["scan_id"]
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-open-report":
            table = self.query_one("#tbl-history", DataTable)
            if table.cursor_row is not None and table.cursor_row < len(table.rows):
                row_key = list(table.rows.keys())[table.cursor_row]
                scan_id = str(row_key.value)
                self.app.push_screen(ReportViewerScreen(scan_id))
        elif event.button.id == "btn-ask-ai":
            table = self.query_one("#tbl-history", DataTable)
            if table.cursor_row is not None and table.cursor_row < len(table.rows):
                row_key = list(table.rows.keys())[table.cursor_row]
                scan_id = str(row_key.value)
                self.app.push_screen(AIChatScreen(default_scan_id=scan_id))


# ==============================================================================
# Screen 5: Report Viewer
# ==============================================================================

class ReportViewerScreen(Screen):
    """Full-screen Markdown report viewer."""

    def __init__(self, scan_id: str):
        super().__init__()
        self.scan_id = scan_id

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="terminal-container"):
            yield Static(f"\n[bold cyan]=== [>] ASSESSMENT REPORT: {self.scan_id} ===[/bold cyan]\n")
            yield Markdown(id="md-report-viewer")
            with Horizontal(classes="nav-bar"):
                yield Button("[A] Consult AI Analyst", id="btn-report-ai", variant="primary")
                yield Button("[Esc] Return", id="btn-back")
        yield Footer()

    async def on_mount(self) -> None:
        config = get_config()
        report_file = config.scans_dir / self.scan_id / "final_report.md"
        viewer = self.query_one("#md-report-viewer", Markdown)
        if report_file.exists():
            content = report_file.read_text(encoding="utf-8", errors="replace")
            viewer.update(content)
        else:
            viewer.update(f"# Report {self.scan_id}\n*Report file not found.*")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-report-ai":
            self.app.push_screen(AIChatScreen(default_scan_id=self.scan_id))


# ==============================================================================
# Screen 6: AI Security Analyst Console
# ==============================================================================

class AIChatScreen(Screen):
    """Terminal-style interactive AI security console."""

    def __init__(self, default_scan_id: Optional[str] = None):
        super().__init__()
        self.default_scan_id = default_scan_id or ""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="terminal-container"):
            yield Static("\n[bold cyan]=== [>] NVIDIA NIM AI SECURITY ANALYST CONSOLE ===[/bold cyan]")
            yield Static("[dim]Evidence-grounded vulnerability explanation & attack path correlation[/dim]\n")

            with Horizontal():
                yield Label("[bold green][+][/bold green] Scan Context ID: ")
                yield Input(value=self.default_scan_id, placeholder="e.g. SCN-20261107-09389", id="txt-ai-scan-id")

            yield Log(id="ai-console-log")

            yield Label("[bold green]rootscan (ai)> [/bold green]")
            yield Input(placeholder="Ask a technical or beginner question regarding this assessment...", id="txt-ai-query")

            with Horizontal(classes="nav-bar"):
                yield Button("[Enter] Submit Query", id="btn-ai-send", variant="primary")
                yield Button("[Esc] Back", id="btn-back")

        yield Footer()

    async def on_mount(self) -> None:
        log = self.query_one("#ai-console-log", Log)
        log.write_line("[bold green][+][/bold green] AI Console Initialized.")
        if self.default_scan_id:
            log.write_line(f"[bold cyan][>][/bold cyan] Loaded assessment context: [bold white]{self.default_scan_id}[/bold white]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-ai-send":
            self._submit()

    def _submit(self):
        scan_id = self.query_one("#txt-ai-scan-id", Input).value.strip()
        query = self.query_one("#txt-ai-query", Input).value.strip()
        if not scan_id or not query:
            self.notify("[!] Scan ID and Query are both required.", severity="warning")
            return

        log = self.query_one("#ai-console-log", Log)
        log.write_line(f"\n[bold green]user> [/bold green]{query}")
        self.query_one("#txt-ai-query", Input).value = ""

        asyncio.create_task(self._query(scan_id, query))

    async def _query(self, scan_id: str, question: str):
        config = get_config()
        storage = ReportStorage(config.scans_dir)
        report_data = storage.load_stage_json(scan_id, "final_report.json")
        context_str = json.dumps(report_data, indent=2, default=str) if report_data else f"Scan {scan_id} metadata."

        client = NimClient()
        log = self.query_one("#ai-console-log", Log)
        log.write_line(f"[dim][>] Querying NVIDIA NIM ({client.model})...[/dim]")

        answer = await client.ask_historical_question(
            report_context=context_str,
            chat_history=[],
            user_question=question
        )
        log.write_line(f"\n[bold cyan]analyst ({client.model})>[/bold cyan]\n{answer}\n")


# ==============================================================================
# Screen 7: Security Tool Registry
# ==============================================================================

class ToolRegistryScreen(Screen):
    """Terminal registry and health check of registered security scanners."""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="terminal-container"):
            yield Static("\n[bold cyan]=== [>] REGISTERED SECURITY SCANNER HEALTH CHECK ===[/bold cyan]\n")
            yield DataTable(id="tbl-tools-health")
            with Horizontal(classes="nav-bar"):
                yield Button("[Esc] Back to Dashboard", id="btn-back")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#tbl-tools-health", DataTable)
        table.add_columns("TOOL", "BINARY", "PURPOSE", "STATUS", "DETECTED VERSION")

        adapters = [
            NmapAdapter(), NucleiAdapter(), HttpxAdapter(),
            RustScanAdapter(), NaabuAdapter(), WhatWebAdapter(), NiktoAdapter()
        ]

        for adp in adapters:
            status_text = Text("INSTALLED", style="bold green") if adp.is_available else Text("NOT FOUND", style="bold red")
            version_str = await adp.get_version() if adp.is_available else "Run install.sh"
            table.add_row(
                Text(adp.name, style="bold cyan"),
                adp.binary_name,
                "Security Scanner",
                status_text,
                version_str[:35]
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()


# ==============================================================================
# Screen 8: Settings
# ==============================================================================

class SettingsScreen(Screen):
    """Terminal configuration inspector."""

    def compose(self) -> ComposeResult:
        config = get_config()
        yield Header()
        with ScrollableContainer(id="terminal-container"):
            yield Static("\n[bold cyan]=== [>] ROOTSCAN SYSTEM CONFIGURATION ===[/bold cyan]\n")
            with Vertical(classes="terminal-meta-box"):
                yield Label(f"[bold green][+][/bold green] Database File : [cyan]{config.database_path}[/cyan]")
                yield Label(f"[bold green][+][/bold green] Scans Storage  : [cyan]{config.scans_dir}[/cyan]")
                yield Label(f"[bold green][+][/bold green] AI Provider    : [bold white]NVIDIA NIM[/bold white]")
                yield Label(f"[bold green][+][/bold green] AI Model       : [cyan]{config.nvidia_nim_model}[/cyan]")
                yield Label(f"[bold green][+][/bold green] NIM Base URL   : [dim]{config.nvidia_nim_base_url}[/dim]")
                yield Label(f"[bold green][+][/bold green] Private Ranges : [{'green' if config.allow_private_ranges else 'yellow'}]{config.allow_private_ranges}[/{'green' if config.allow_private_ranges else 'yellow'}]")

            with Horizontal(classes="nav-bar"):
                yield Button("[Esc] Back to Dashboard", id="btn-back")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()


# ==============================================================================
# RootScan Main Application
# ==============================================================================

class RootScanApp(App):
    """RustScan-inspired Terminal Application for RootScan."""

    CSS = RUSTSCAN_CSS
    BINDINGS = [
        Binding("1", "nav_new", "New Scan", show=True),
        Binding("2", "nav_history", "History", show=True),
        Binding("3", "nav_ai", "AI Analyst", show=True),
        Binding("4", "nav_tools", "Tools", show=True),
        Binding("5", "nav_settings", "Settings", show=True),
        Binding("escape", "back", "Back", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def on_mount(self) -> None:
        self.push_screen(DashboardScreen())

    def action_nav_new(self) -> None:
        self.push_screen(NewScanScreen())

    def action_nav_history(self) -> None:
        self.push_screen(HistoryScreen())

    def action_nav_ai(self) -> None:
        self.push_screen(AIChatScreen())

    def action_nav_tools(self) -> None:
        self.push_screen(ToolRegistryScreen())

    def action_nav_settings(self) -> None:
        self.push_screen(SettingsScreen())

    def action_back(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()
