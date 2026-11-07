"""Command-line interface (CLI) for RootScan."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
import json
import os
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.ai.nim_client import NimClient
from app.core.configuration import get_config
from app.core.event_bus import EventType, ScanEvent, get_event_bus
from app.core.orchestrator import ScanOrchestrator
from app.database.repository import DatabaseRepository
from app.reports.storage import ReportStorage
from app.scanners.httpx import HttpxAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter


console = Console()


def print_banner():
    banner = """[bold cyan]
  ____             _   ____                  
 |  _ \\ ___   ___ | |_/ ___|  ___ __ _ _ __  
 | |_) / _ \\ / _ \\| __\\___ \\ / __/ _` | '_ \\ 
 |  _ < (_) | (_) | |_ ___) | (_| (_| | | | |
 |_| \\_\\___/ \\___/ \\__|____/ \\___\\__,_|_| |_|
[/bold cyan]
[dim]AI-Powered Security Assessment & Pentesting Toolkit v1.0.0[/dim]
"""
    console.print(banner)


async def cli_scan(target: str, profile: str, allow_private: bool):
    """Execute assessment in CLI mode with real-time Rich formatting."""
    print_banner()
    console.print(f"[bold yellow][*] Initializing assessment for target:[/bold yellow] [bold white]{target}[/bold white]")
    console.print(f"[dim]Profile: {profile} | Allow Private IP: {allow_private}[/dim]\n")

    event_bus = get_event_bus()

    async def log_event(event: ScanEvent):
        if event.event_type == EventType.STAGE_STARTED:
            console.print(f"[bold blue]>>> Stage:[/bold blue] {event.stage_name} - [dim]{event.message}[/dim]")
        elif event.event_type == EventType.TOOL_STARTED:
            console.print(f"  [cyan][Tool][/cyan] Executing {event.tool_name}...")
        elif event.event_type == EventType.TOOL_COMPLETED:
            console.print(f"  [green][Done][/green] {event.tool_name} finished successfully.")
        elif event.event_type == EventType.TOOL_FAILED:
            console.print(f"  [red][Warning][/red] {event.tool_name}: {event.message or 'exited with error'}")
        elif event.event_type == EventType.SCAN_COMPLETED:
            console.print(f"\n[bold green][✓] Assessment complete![/bold green] {event.message}")

    event_bus.subscribe_all(log_event)

    orchestrator = ScanOrchestrator()
    success, scan_id, report = await orchestrator.execute_scan(
        raw_target=target,
        profile_name=profile,
        allow_private=allow_private
    )

    if not success or not report:
        console.print("[bold red][!] Assessment failed during validation or execution.[/bold red]")
        sys.exit(1)

    # Render summary table
    table = Table(title=f"Scan Summary: {scan_id}", border_style="cyan")
    table.add_column("Port/Service", style="white")
    table.add_column("State", style="green")
    table.add_column("Banner / Details", style="dim")

    for s in report.services:
        table.add_row(f"{s.port}/{s.protocol} ({s.service_name})", s.state, s.banner or "-")

    console.print(table)

    if report.findings:
        f_table = Table(title="Identified Security Findings", border_style="red")
        f_table.add_column("Severity", style="bold")
        f_table.add_column("Finding", style="white")
        f_table.add_column("Tool", style="yellow")
        f_table.add_column("CVE", style="cyan")

        for f in report.findings:
            sev_color = "red" if f.severity.value in ("critical", "high") else "yellow"
            f_table.add_row(f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]", f.title, f.source_tool, f.cve_id or "-")

        console.print(f_table)

    console.print(f"\n[bold green][*] Full reports saved to:[/bold green] data/scans/{scan_id}/")


def cli_history():
    """List historical scans stored in SQLite."""
    print_banner()
    config = get_config()
    db = DatabaseRepository(config.database_path)
    scans = db.list_scans(limit=25)

    if not scans:
        console.print("[yellow]No historical assessments found.[/yellow]")
        return

    table = Table(title="Assessment History", border_style="blue")
    table.add_column("Scan ID", style="bold cyan")
    table.add_column("Target", style="white")
    table.add_column("Profile", style="dim")
    table.add_column("Status", style="green")
    table.add_column("Findings", style="yellow")
    table.add_column("AI", style="magenta")
    table.add_column("Date", style="dim")

    for s in scans:
        table.add_row(
            s["scan_id"],
            s["target"],
            s["profile"],
            s["status"],
            str(s["finding_count"]),
            s["ai_status"],
            s["start_time"][:19]
        )

    console.print(table)


async def cli_tools():
    """Check availability of registered tools."""
    print_banner()
    table = Table(title="RootScan Security Tools Registry", border_style="cyan")
    table.add_column("Tool Name", style="bold white")
    table.add_column("Binary", style="dim")
    table.add_column("Status", style="bold")
    table.add_column("Version", style="dim")

    adapters = [NmapAdapter(), NucleiAdapter(), HttpxAdapter()]
    for adp in adapters:
        if adp.is_available:
            ver = await adp.get_version()
            table.add_row(adp.name, adp.binary_name, "[green]INSTALLED[/green]", ver[:30])
        else:
            table.add_row(adp.name, adp.binary_name, "[red]NOT FOUND[/red]", "Run install.sh")

    console.print(table)


async def cli_ai_test():
    """Test NVIDIA NIM API connectivity."""
    print_banner()
    client = NimClient()
    console.print(f"Checking NVIDIA NIM Configuration...")
    console.print(f"- Base URL: {client.base_url}")
    console.print(f"- Model: {client.model}")
    console.print(f"- Configured: {'[green]Yes[/green]' if client.is_configured else '[red]No (Key missing)[/red]'}\n")

    if not client.is_configured:
        console.print("[red][!] NVIDIA_NIM_API_KEY is not configured in .env[/red]")
        return

    with console.status("[bold cyan]Connecting to NVIDIA NIM..."):
        ok, msg = await client.verify_connection()

    if ok:
        console.print(f"[bold green][✓] {msg}[/bold green]")
    else:
        console.print(f"[bold red][✗] {msg}[/bold red]")


def run_cli():
    """CLI Argument parser entrypoint."""
    parser = argparse.ArgumentParser(description="RootScan - AI-Powered Security Assessment Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Execute an assessment against a target")
    scan_p.add_argument("target", help="IP address or domain name")
    scan_p.add_argument("--profile", default="quick", choices=["quick", "standard", "deep", "custom"], help="Assessment profile")
    scan_p.add_argument("--allow-private", action="store_true", help="Authorize scanning private IP ranges")

    # history command
    subparsers.add_parser("history", help="List scan history")

    # tools command
    subparsers.add_parser("tools", help="Check security tool status")

    # ai-test command
    subparsers.add_parser("ai-test", help="Test NVIDIA NIM AI connectivity")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(cli_scan(args.target, args.profile, args.allow_private))
    elif args.command == "history":
        cli_history()
    elif args.command == "tools":
        asyncio.run(cli_tools())
    elif args.command == "ai-test":
        asyncio.run(cli_ai_test())
    else:
        parser.print_help()

