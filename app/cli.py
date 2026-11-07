"""Command-line interface (CLI) for RootScan with RustScan-inspired terminal styling."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
import json
import os
import sys
from typing import Optional

from rich.console import Console
from rich.table import Table

from app.ai.nim_client import NimClient
from app.core.configuration import get_config
from app.core.event_bus import EventType, ScanEvent, get_event_bus
from app.core.orchestrator import ScanOrchestrator
from app.database.repository import DatabaseRepository
from app.reports.comparator import ReportComparator
from app.reports.schemas import FinalReport
from app.reports.storage import ReportStorage
from app.scanners.httpx import HttpxAdapter
from app.scanners.naabu import NaabuAdapter
from app.scanners.nikto import NiktoAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter
from app.scanners.rustscan import RustScanAdapter
from app.scanners.whatweb import WhatWebAdapter


console = Console()


def print_banner():
    banner = """[bold cyan]
  ____             _   ____                  
 |  _ \\ ___   ___ | |_/ ___|  ___ __ _ _ __  
 | |_) / _ \\ / _ \\| __\\___ \\ / __/ _` | '_ \\ 
 |  _ < (_) | (_) | |_ ___) | (_| (_| | | | |
 |_| \\_\\___/ \\___/ \\__|____/ \\___\\__,_|_| |_|
[/bold cyan]
[dim]RootScan v1.0.0 — Automated Security Assessment & Pentesting Toolkit[/dim]
"""
    console.print(banner)


async def cli_scan(target: str, profile: str, allow_private: bool):
    """Execute assessment in CLI mode with RustScan-style terminal output."""
    print_banner()
    console.print(f"[bold green][+][/bold green] [bold white]ROOTSCAN v1.0[/bold white]")
    console.print(f"[bold yellow][*][/bold yellow] Initializing security assessment for target: [bold cyan]{target}[/bold cyan]")
    console.print(f"[bold yellow][*][/bold yellow] Configuration: Profile=[bold white]{profile}[/bold white], Private Scope Permitted=[bold white]{allow_private}[/bold white]\n")

    event_bus = get_event_bus()

    async def log_event(event: ScanEvent):
        if event.event_type == EventType.STAGE_STARTED:
            console.print(f"[bold cyan][>][/bold cyan] Entering stage: [bold white]{event.stage_name}[/bold white] [dim]({event.message or ''})[/dim]")
        elif event.event_type == EventType.TOOL_STARTED:
            console.print(f"  [bold cyan][>][/bold cyan] Executing [bold cyan]{event.tool_name}[/bold cyan]...")
        elif event.event_type == EventType.TOOL_OUTPUT:
            line = event.message or ""
            if "/tcp" in line or "/udp" in line or "OPEN" in line:
                console.print(f"  [bold green][+][/bold green] {line}")
            else:
                console.print(f"      [dim]{line}[/dim]")
        elif event.event_type == EventType.TOOL_COMPLETED:
            console.print(f"  [bold green][+][/bold green] {event.tool_name} completed.")
        elif event.event_type == EventType.TOOL_FAILED:
            console.print(f"  [bold red][-][/bold red] {event.tool_name}: {event.message or 'exited with error'}")
        elif event.event_type == EventType.SCAN_COMPLETED:
            console.print(f"\n[bold green][+][/bold green] [bold white]Assessment completed successfully.[/bold white]")

    event_bus.subscribe_all(log_event)

    orchestrator = ScanOrchestrator()
    success, scan_id, report = await orchestrator.execute_scan(
        raw_target=target,
        profile_name=profile,
        allow_private=allow_private
    )

    if not success or not report:
        console.print("[bold red][-][/bold red] Assessment aborted during validation or execution.")
        sys.exit(1)

    console.print(f"\n[bold green][+][/bold green] [bold white]DISCOVERED SERVICES & OPEN PORTS[/bold white]")
    if report.services:
        table = Table(border_style="dim", header_style="bold cyan", box=None)
        table.add_column("PORT", style="bold green")
        table.add_column("STATE", style="white")
        table.add_column("SERVICE", style="cyan")
        table.add_column("VERSION / BANNER", style="dim")
        for s in report.services:
            table.add_row(f"{s.port}/{s.protocol.upper()}", s.state.upper(), s.service_name or "unknown", s.banner or s.service_version or "-")
        console.print(table)
    else:
        console.print("  [dim]No open ports or services detected in this scope.[/dim]")

    if report.findings:
        console.print(f"\n[bold red][-][/bold red] [bold white]SECURITY VULNERABILITIES & MISCONFIGURATIONS ({len(report.findings)})[/bold white]")
        for f in report.findings:
            sev_color = "bold red" if f.severity.value in ("critical", "high") else "yellow"
            cve_str = f" ({f.cve_id})" if f.cve_id else ""
            console.print(f"  [{sev_color}][!][/{sev_color}] [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}{cve_str} [dim]via {f.source_tool}[/dim]")
            if f.evidence:
                console.print(f"      [dim]{f.evidence[:100]}...[/dim]")

    console.print(f"\n[bold green][+][/bold green] [bold white]Full reports saved:[/bold white]")
    console.print(f"  [bold cyan]->[/bold cyan] JSON: data/scans/{scan_id}/final_report.json")
    console.print(f"  [bold cyan]->[/bold cyan] Markdown: data/scans/{scan_id}/final_report.md")
    console.print(f"  [bold cyan]->[/bold cyan] Standalone HTML: data/scans/{scan_id}/final_report.html")
    if os.path.exists(f"data/scans/{scan_id}/ai_analysis.json"):
        console.print(f"  [bold cyan]->[/bold cyan] AI Analysis: data/scans/{scan_id}/ai_analysis.json")


def cli_history():
    """List historical scans stored in SQLite."""
    print_banner()
    config = get_config()
    db = DatabaseRepository(config.database_path)
    scans = db.list_scans(limit=25)

    if not scans:
        console.print("[bold yellow][*][/bold yellow] No historical assessments found in repository.")
        return

    console.print("[bold green][+][/bold green] [bold white]ASSESSMENT LOG ARCHIVE[/bold white]\n")
    table = Table(border_style="dim", header_style="bold cyan")
    table.add_column("SCAN ID", style="bold cyan")
    table.add_column("TARGET", style="white")
    table.add_column("PROFILE", style="dim")
    table.add_column("STATUS", style="bold green")
    table.add_column("FINDINGS", style="yellow")
    table.add_column("AI", style="magenta")
    table.add_column("TIMESTAMP", style="dim")

    for s in scans:
        status_color = "green" if s["status"] == "completed" else "yellow"
        table.add_row(
            s["scan_id"],
            s["target"],
            s["profile"],
            f"[{status_color}]{s['status'].upper()}[/{status_color}]",
            str(s["finding_count"]),
            s["ai_status"],
            s["start_time"][:19]
        )

    console.print(table)


async def cli_tools():
    """Check availability of registered tools."""
    print_banner()
    console.print("[bold green][+][/bold green] [bold white]SECURITY SCANNER REGISTRY HEALTH CHECK[/bold white]\n")

    adapters = [
        NmapAdapter(), NucleiAdapter(), HttpxAdapter(),
        RustScanAdapter(), NaabuAdapter(), WhatWebAdapter(), NiktoAdapter()
    ]

    for adp in adapters:
        if adp.is_available:
            ver = await adp.get_version()
            console.print(f"[bold green][+][/bold green] {adp.name:<10} : [bold green]INSTALLED[/bold green] [dim]({ver[:35]})[/dim]")
        else:
            console.print(f"[bold red][-][/bold red] {adp.name:<10} : [bold red]NOT FOUND[/bold red] [dim](Run install.sh to install)[/dim]")


async def cli_ai_test():
    """Test NVIDIA NIM API connectivity."""
    print_banner()
    client = NimClient()
    console.print("[bold green][+][/bold green] [bold white]NVIDIA NIM AI SYSTEM CHECK[/bold white]")
    console.print(f"  [bold cyan][>][/bold cyan] Endpoint : {client.base_url}")
    console.print(f"  [bold cyan][>][/bold cyan] Model    : {client.model}")
    console.print(f"  [bold cyan][>][/bold cyan] Auth Key : {'[bold green]Configured[/bold green]' if client.is_configured else '[bold red]Missing[/bold red]'}\n")

    if not client.is_configured:
        console.print("[bold red][-][/bold red] NVIDIA_NIM_API_KEY is missing from .env")
        return

    with console.status("[bold cyan][>] Handshaking with NVIDIA NIM..."):
        ok, msg = await client.verify_connection()

    if ok:
        console.print(f"[bold green][+][/bold green] {msg}")
    else:
        console.print(f"[bold red][-][/bold red] {msg}")


def cli_compare(scan_id_1: str, scan_id_2: str):
    """Diff two historical scan reports (FR-18)."""
    print_banner()
    config = get_config()
    storage = ReportStorage(config.scans_dir)

    r1_data = storage.load_stage_json(scan_id_1, "final_report.json")
    r2_data = storage.load_stage_json(scan_id_2, "final_report.json")

    if not r1_data or not r2_data:
        console.print("[bold red][-][/bold red] One or both scan IDs could not be loaded from storage.")
        return

    r1 = FinalReport.model_validate(r1_data)
    r2 = FinalReport.model_validate(r2_data)

    diff = ReportComparator.compare(r1, r2)
    console.print(f"[bold green][+][/bold green] [bold white]ASSESSMENT COMPARISON DIFF[/bold white]")
    console.print(f"  [bold cyan][>][/bold cyan] Baseline Scan : {scan_id_1}")
    console.print(f"  [bold cyan][>][/bold cyan] Compare Scan  : {scan_id_2}")
    delta_style = "bold red" if diff.risk_delta == "INCREASED" else "bold green"
    console.print(f"  [bold cyan][>][/bold cyan] Risk Delta    : [{delta_style}]{diff.risk_delta}[/{delta_style}]\n")

    if diff.new_open_ports:
        console.print(f"[bold red][!][/bold red] Newly Opened Ports : {diff.new_open_ports}")
    if diff.closed_ports:
        console.print(f"[bold green][+][/bold green] Closed/Secured Ports: {diff.closed_ports}")
    if diff.new_findings:
        console.print(f"[bold red][!][/bold red] New Vulnerabilities: {len(diff.new_findings)}")
        for f in diff.new_findings:
            console.print(f"    - [{f.severity.value.upper()}] {f.title}")
    if diff.resolved_findings:
        console.print(f"[bold green][+][/bold green] Resolved Findings  : {len(diff.resolved_findings)}")
        for f in diff.resolved_findings:
            console.print(f"    - {f.title}")


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

    # compare command
    comp_p = subparsers.add_parser("compare", help="Diff two historical assessments")
    comp_p.add_argument("scan1", help="Baseline Scan ID")
    comp_p.add_argument("scan2", help="Compare Scan ID")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(cli_scan(args.target, args.profile, args.allow_private))
    elif args.command == "history":
        cli_history()
    elif args.command == "tools":
        asyncio.run(cli_tools())
    elif args.command == "ai-test":
        asyncio.run(cli_ai_test())
    elif args.command == "compare":
        cli_compare(args.scan1, args.scan2)
    else:
        parser.print_help()
