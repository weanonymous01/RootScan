"""Main Textual Terminal User Interface (TUI) for RootScan."""

from __future__ import annotations

import asyncio
from datetime import datetime
import json
import os
from typing import Any, Dict, List, Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    ProgressBar,
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
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter


TUI_CSS = """
Screen {
    background: #0b0f19;
    color: #e2e8f0;
}

Header {
    background: #111827;
    color: #00d4aa;
    text-style: bold;
    dock: top;
    height: 3;
}

Footer {
    background: #111827;
    color: #94a3b8;
    dock: bottom;
    height: 1;
}

#dashboard-container {
    padding: 1 2;
}

.panel-box {
    background: #151d2f;
    border: solid #1e293b;
    padding: 1 2;
    margin-bottom: 1;
}

.metric-title {
    color: #94a3b8;
    text-style: bold;
}

.metric-value {
    color: #00d4aa;
    text-style: bold;
}

Button {
    background: #1e293b;
    color: #f8fafc;
    border: none;
    margin: 1;
    min-width: 20;
}

Button:hover {
    background: #00d4aa;
    color: #0b0f19;
}

Button.-primary {
    background: #2563eb;
    color: white;
}

Button.-primary:hover {
    background: #3b82f6;
}

Button.-danger {
    background: #991b1b;
    color: white;
}

Button.-danger:hover {
    background: #dc2626;
}

Input {
    background: #1e293b;
    border: tall #334155;
    color: #f8fafc;
    margin: 1 0;
}

Input:focus {
    border: tall #00d4aa;
}

DataTable {
    background: #151d2f;
    border: solid #1e293b;
}

Log {
    background: #080c14;
    border: solid #1e293b;
    color: #a5f3fc;
    min-height: 15;
}
"""


class DashboardScreen(Screen):
    """Main Dashboard view of RootScan."""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with ScrollableContainer(id="dashboard-container"):
            # Header Title banner
            yield Static(
                "[bold cyan]ROOTSCAN[/bold cyan] [dim]| AI-Powered Security Assessment & Pentesting Toolkit[/dim]\n"
                "[dim]Local Execution • Transparent Evidence • NVIDIA NIM Intelligence[/dim]\n",
                classes="panel-box"
            )

            # System Status & Metrics Panel
            with Horizontal(classes="panel-box"):
                with Vertical():
                    yield Label("SYSTEM STATUS", classes="metric-title")
                    yield Label("● Operational", id="status-label", classes="metric-value")
                with Vertical():
                    yield Label("INSTALLED TOOLS", classes="metric-title")
                    yield Label("Checking...", id="tools-metric", classes="metric-value")
                with Vertical():
                    yield Label("NVIDIA NIM AI", classes="metric-title")
                    yield Label("Checking...", id="ai-metric", classes="metric-value")
                with Vertical():
                    yield Label("COMPLETED SCANS", classes="metric-title")
                    yield Label("0", id="scans-metric", classes="metric-value")

            # Main Navigation Action Buttons
            yield Label("[bold white]OPERATIONS MENU[/bold white]")
            with Horizontal():
                yield Button("1. New Assessment", id="btn-new-scan", variant="primary")
                yield Button("2. Scan History", id="btn-history")
                yield Button("3. AI Analyst Chat", id="btn-ai-chat")
            with Horizontal():
                yield Button("4. Tool Registry", id="btn-tools")
                yield Button("5. Settings", id="btn-settings")
                yield Button("6. Exit", id="btn-exit", variant="error")

            # Recent scans table
            yield Label("\n[bold white]RECENT ASSESSMENTS[/bold white]")
            yield DataTable(id="dashboard-scans-table")

        yield Footer()

    async def on_mount(self) -> None:
        """Populate initial metrics and scans table."""
        config = get_config()
        db = DatabaseRepository(config.database_path)

        # Scans count & table
        scans = db.list_scans(limit=5)
        self.query_one("#scans-metric", Label).update(str(len(scans)))

        table = self.query_one("#dashboard-scans-table", DataTable)
        table.add_columns("Scan ID", "Target", "Profile", "Status", "Findings", "Date")
        for s in scans:
            table.add_row(
                s["scan_id"], s["target"], s["profile"],
                s["status"], str(s["finding_count"]), s["start_time"][:19]
            )

        # Tool count
        installed_count = sum(1 for adp in [NmapAdapter(), NucleiAdapter(), HttpxAdapter()] if adp.is_available)
        self.query_one("#tools-metric", Label).update(f"{installed_count} / 3 Ready")

        # AI check
        client = NimClient()
        if client.is_configured:
            self.query_one("#ai-metric", Label).update("[green]Connected[/green]")
        else:
            self.query_one("#ai-metric", Label).update("[yellow]Key Missing[/yellow]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-new-scan":
            self.app.push_screen(NewScanScreen())
        elif btn_id == "btn-history":
            self.app.push_screen(HistoryScreen())
        elif btn_id == "btn-ai-chat":
            self.app.push_screen(AIChatScreen())
        elif btn_id == "btn-tools":
            self.app.push_screen(ToolRegistryScreen())
        elif btn_id == "btn-settings":
            self.app.push_screen(SettingsScreen())
        elif btn_id == "btn-exit":
            self.app.exit()


class NewScanScreen(Screen):
    """Screen to configure and launch a new security assessment."""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="dashboard-container"):
            yield Label("[bold cyan]LAUNCH NEW SECURITY ASSESSMENT[/bold cyan]\n")
            yield Label("Target Address (Domain or IP):")
            yield Input(placeholder="e.g. scanme.nmap.org or 192.168.1.50", id="target-input")

            yield Label("\nAssessment Profile:")
            with RadioSet(id="profile-select"):
                yield RadioButton("Quick (Top 100 ports, fast recon, essential checks)", id="quick", value=True)
                yield RadioButton("Standard (Top 1000 ports, service enumeration, Nuclei)", id="standard")
                yield RadioButton("Deep (Full 1-65535 ports, thorough templates)", id="deep")

            yield Label("\nInternal Scope Authorization:")
            with Horizontal():
                yield Switch(id="private-switch")
                yield Label("  Authorize Private/Internal Network Scanning (RFC 1918)")

            with Horizontal():
                yield Button("Start Assessment", id="btn-start", variant="primary")
                yield Button("Cancel", id="btn-back")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-start":
            target = self.query_one("#target-input", Input).value.strip()
            if not target:
                self.notify("Target cannot be empty!", severity="error")
                return

            profile_radioset = self.query_one("#profile-select", RadioSet)
            selected_radio = profile_radioset.pressed_button
            profile_name = selected_radio.id if selected_radio else "quick"
            allow_private = self.query_one("#private-switch", Switch).value

            self.app.push_screen(LiveScanScreen(target=target, profile=profile_name, allow_private=allow_private))


class LiveScanScreen(Screen):
    """Real-time assessment monitoring screen with streaming logs and findings."""

    def __init__(self, target: str, profile: str, allow_private: bool):
        super().__init__()
        self.target = target
        self.profile = profile
        self.allow_private = allow_private
        self.scan_id = "SCN-INITIALIZING"
        self.orchestrator = ScanOrchestrator()

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="dashboard-container"):
            yield Static(f"[bold cyan]LIVE ASSESSMENT:[/bold cyan] {self.target} | Profile: {self.profile}", id="live-header", classes="panel-box")
            
            with Horizontal():
                yield Label("Stage: [bold blue]Initializing...[/bold blue]", id="live-stage-label")
                yield Button("Cancel Assessment", id="btn-cancel-scan", variant="error")

            yield Label("\n[bold white]Real-Time Scanner Event Stream[/bold white]")
            yield Log(id="scan-log")

            yield Label("\n[bold white]Discovered Services[/bold white]")
            yield DataTable(id="live-services-table")

        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#live-services-table", DataTable)
        table.add_columns("Port", "Service", "Version", "Banner")

        event_bus = get_event_bus()

        async def on_event(event: ScanEvent):
            log = self.query_one("#scan-log", Log)
            if event.event_type == EventType.STAGE_STARTED:
                self.query_one("#live-stage-label", Label).update(f"Stage: [bold blue]{event.stage_name}[/bold blue]")
                log.write_line(f"[bold blue]>>> Stage Started:[/bold blue] {event.stage_name} ({event.message or ''})")
            elif event.event_type == EventType.TOOL_OUTPUT:
                log.write_line(f"  [dim]{event.message}[/dim]")
            elif event.event_type == EventType.TOOL_COMPLETED:
                log.write_line(f"[bold green][✓] {event.tool_name} completed.[/bold green]")
            elif event.event_type == EventType.TOOL_FAILED:
                log.write_line(f"[bold red][!] {event.tool_name} failed: {event.message or ''}[/bold red]")
            elif event.event_type == EventType.SCAN_COMPLETED:
                log.write_line(f"[bold green][✓] Assessment finished![/bold green] Results saved.")

        event_bus.subscribe_all(on_event)

        # Run scan in background task
        asyncio.create_task(self._run_scan())

    async def _run_scan(self):
        success, scan_id, report = await self.orchestrator.execute_scan(
            raw_target=self.target,
            profile_name=self.profile,
            allow_private=self.allow_private
        )
        if success and report:
            self.scan_id = scan_id
            table = self.query_one("#live-services-table", DataTable)
            for s in report.services:
                table.add_row(f"{s.port}/{s.protocol}", s.service_name or "unknown", s.service_version or "-", s.banner or "-")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-scan":
            asyncio.create_task(self.orchestrator.cancel_scan(self.scan_id))
            self.notify("Scan cancellation requested.", severity="warning")
            self.app.pop_screen()


class HistoryScreen(Screen):
    """View and inspect completed assessments."""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="dashboard-container"):
            yield Label("[bold cyan]ASSESSMENT HISTORY[/bold cyan]\n")
            yield DataTable(id="history-table")
            with Horizontal():
                yield Button("Back to Dashboard", id="btn-back")

        yield Footer()

    async def on_mount(self) -> None:
        config = get_config()
        db = DatabaseRepository(config.database_path)
        scans = db.list_scans(limit=50)

        table = self.query_one("#history-table", DataTable)
        table.add_columns("Scan ID", "Target", "Profile", "Status", "Findings", "AI Analysis", "Date")
        for s in scans:
            table.add_row(
                s["scan_id"], s["target"], s["profile"], s["status"],
                str(s["finding_count"]), s["ai_status"], s["start_time"][:19]
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()


class AIChatScreen(Screen):
    """Interactive AI Security Analyst Chat grounded in scan reports."""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="dashboard-container"):
            yield Label("[bold cyan]AI SECURITY ANALYST INTERACTIVE CHAT[/bold cyan]")
            yield Label("Grounded evidence-based guidance powered by NVIDIA NIM\n")
            
            yield Label("Enter Scan ID to load assessment context:")
            yield Input(placeholder="e.g. SCN-20261107-A8F29", id="chat-scan-id-input")
            
            yield Log(id="ai-chat-log")
            
            yield Input(placeholder="Ask the AI Security Analyst a question about this assessment...", id="chat-question-input")
            with Horizontal():
                yield Button("Send Question", id="btn-send-question", variant="primary")
                yield Button("Back to Dashboard", id="btn-back")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-send-question":
            self._handle_send()

    def _handle_send(self):
        scan_id = self.query_one("#chat-scan-id-input", Input).value.strip()
        question = self.query_one("#chat-question-input", Input).value.strip()
        if not scan_id or not question:
            self.notify("Both Scan ID and Question are required.", severity="warning")
            return

        chat_log = self.query_one("#ai-chat-log", Log)
        chat_log.write_line(f"\n[bold green]User:[/bold green] {question}")
        self.query_one("#chat-question-input", Input).value = ""

        asyncio.create_task(self._query_ai(scan_id, question))

    async def _query_ai(self, scan_id: str, question: str):
        config = get_config()
        storage = ReportStorage(config.scans_dir)
        report_data = storage.load_stage_json(scan_id, "final_report.json")
        context_str = json.dumps(report_data, indent=2, default=str) if report_data else f"Scan {scan_id} metadata."

        client = NimClient()
        chat_log = self.query_one("#ai-chat-log", Log)
        chat_log.write_line("[dim]Consulting NVIDIA NIM Security Analyst...[/dim]")

        answer = await client.ask_historical_question(
            report_context=context_str,
            chat_history=[],
            user_question=question
        )
        chat_log.write_line(f"\n[bold cyan]AI Analyst ({client.model}):[/bold cyan]\n{answer}\n")


class ToolRegistryScreen(Screen):
    """View registered security tools and their installation status."""

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="dashboard-container"):
            yield Label("[bold cyan]SECURITY TOOL REGISTRY & HEALTH CHECK[/bold cyan]\n")
            yield DataTable(id="tools-table")
            with Horizontal():
                yield Button("Back to Dashboard", id="btn-back")

        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#tools-table", DataTable)
        table.add_columns("Tool", "Binary", "Purpose", "Status", "Version")

        config = get_config()
        for key, tool_info in config.tools.get("tools", {}).items():
            adapter = None
            if key == "nmap":
                adapter = NmapAdapter()
            elif key == "nuclei":
                adapter = NucleiAdapter()
            elif key == "httpx":
                adapter = HttpxAdapter()

            status = "[green]INSTALLED[/green]" if adapter and adapter.is_available else "[red]NOT FOUND[/red]"
            version = await adapter.get_version() if adapter and adapter.is_available else "N/A"
            table.add_row(tool_info.get("name", key), tool_info.get("binary", key), tool_info.get("purpose", ""), status, version[:25])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()


class SettingsScreen(Screen):
    """View and modify RootScan configuration settings."""

    def compose(self) -> ComposeResult:
        config = get_config()
        yield Header()
        with ScrollableContainer(id="dashboard-container"):
            yield Label("[bold cyan]ROOTSCAN CONFIGURATION[/bold cyan]\n")
            yield Label(f"Database Path: {config.database_path}")
            yield Label(f"Scans Directory: {config.scans_dir}")
            yield Label(f"NVIDIA NIM Model: {config.nvidia_nim_model}")
            yield Label(f"NVIDIA NIM Base URL: {config.nvidia_nim_base_url}")
            yield Label(f"Private Ranges Permitted: {config.allow_private_ranges}")
            
            with Horizontal():
                yield Button("Back to Dashboard", id="btn-back")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()


class RootScanApp(App):
    """Main Textual Application for RootScan."""

    CSS = TUI_CSS
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("escape", "back", "Back", show=True),
    ]

    def on_mount(self) -> None:
        self.push_screen(DashboardScreen())

    def action_back(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()

