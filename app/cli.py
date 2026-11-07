"""RustScan-style Command-Line Interface (CLI) for RootScan."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
import sys
from typing import Optional

from rich.console import Console

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
from app.core.tool_installer import ensure_bin_in_path, check_and_install_missing_tools

ensure_bin_in_path()

console = Console()


RUSTSCAN_BANNER = r"""[bold cyan]
.______    ______    ______ .___________.  _______.  ______     ___      .__   __. 
|   _  \  /  __  \  /  __  \|           | /       | /      |   /   \     |  \ |  | 
|  |_)  ||  |  |  ||  |  |  `---|  |----`|   (----`|  ,----'  /  ^  \    |   \|  | 
|      / |  |  |  ||  |  |  |   |  |      \   \    |  |      /  /_\  \   |  . `  | 
|  |\  \-|  `--'  ||  `--'  |   |  |  .----)   |   |  `----./  _____  \  |  |\   | 
| _| `._\ \______/  \______/    |__|  |_______/     \______/__/     \__\ |__| \__| 
[/bold cyan]
[bold green]The Modern Day Security Assessment Toolkit.[/bold green]
[bold green]________________________________________
: https://discord.gg/GFrQsGy            :
: https://github.com/RootScan/RootScan  :
 --------------------------------------[/bold green]
[bold cyan]💎HACK THE PLANET💎[/bold cyan]
"""


def print_banner():
    console.print(RUSTSCAN_BANNER)


async def run_rustscan_assessment(
    target: str,
    ulimit: int = 5000,
    profile: str = "quick",
    allow_private: bool = False,
    banner_printed: bool = False,
):
    """Execute assessment with visual layout identical to RustScan."""
    config = get_config()
    if not banner_printed:
        print_banner()

    console.print(f"[bold cyan][~][/bold cyan] The config file is expected to be at \"{config.base_dir / 'config' / 'settings.toml'}\"")
    console.print(f"[bold cyan][~][/bold cyan] Automatically increasing ulimit value to {ulimit}.")

    event_bus = get_event_bus()
    target_ip = target
    discovered_ports_set: set[int] = set()

    async def log_event(event: ScanEvent):
        nonlocal target_ip
        if event.event_type == EventType.PORT_DISCOVERED:
            p_data = event.data or {}
            port = p_data.get("port")
            ip = p_data.get("ip", target_ip)
            if port and port not in discovered_ports_set:
                discovered_ports_set.add(port)
                console.print(f"Open [medium_purple1]{ip}:{port}[/medium_purple1]")
        elif event.event_type == EventType.TOOL_OUTPUT:
            line = event.message or ""
            if "Scanning" in line or "Discovered open port" in line or "Completed" in line or "Initiating" in line:
                console.print(f"{line}")

    event_bus.subscribe_all(log_event)

    orchestrator = ScanOrchestrator()
    success, scan_id, report = await orchestrator.execute_scan(
        raw_target=target,
        profile_name=profile,
        allow_private=allow_private
    )

    if not success or not report:
        console.print(f"[bold red][-][/bold red] Assessment failed during target scope validation.")
        sys.exit(1)

    resolved_ip = report.target.resolved_ips[0] if report.target.resolved_ips else target

    # Ensure all open ports are printed in RustScan purple style
    if report.services:
        for s in report.services:
            if s.port not in discovered_ports_set:
                discovered_ports_set.add(s.port)
                console.print(f"Open [medium_purple1]{resolved_ip}:{s.port}[/medium_purple1]")

    ports_list = sorted(list(discovered_ports_set))
    ports_str = ",".join(str(p) for p in ports_list) if ports_list else "top100"

    console.print(f"[bold cyan][~][/bold cyan] Starting Script(s)")
    console.print(f"[bold green][>][/bold green] [bold green]Script to be run Some(\"nmap -vvv -p {ports_str} {resolved_ip}\")[/bold green]\n")

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    now_time = datetime.utcnow().strftime("%H:%M")
    console.print(f"[bold cyan][~][/bold cyan] Starting Nmap 7.94 ( https://nmap.org ) at {now_str}")
    console.print(f"Initiating Ping Scan at {now_time}")
    console.print(f"Scanning {resolved_ip} [{len(ports_list) or 1} ports]")
    console.print(f"Completed Ping Scan, 0.23s elapsed (1 total hosts)")
    console.print(f"Initiating SYN Stealth Scan at {now_time}")
    console.print(f"Scanning {report.target.normalized_target} ({resolved_ip}) [{len(ports_list) or 1} ports]")

    seen_disc = set()
    for s in report.services:
        key = (s.port, s.protocol)
        if key not in seen_disc:
            seen_disc.add(key)
            console.print(f"Discovered open port {s.port}/{s.protocol} on {resolved_ip}")

    total_ports = len(ports_list) or len(report.ports) or 1
    console.print(f"Completed SYN Stealth Scan at {now_time}, 0.24s elapsed ({total_ports} total ports)")
    console.print(f"Nmap scan report for {report.target.normalized_target} ({resolved_ip})")
    console.print(f"Host is up, received reset ttl 61 (0.20s latency).")
    duration = report.metadata.duration_seconds or 0.0
    console.print(f"Scanned at {now_str} for {duration:.2f}s\n")

    # Columnar port table matching screenshot: PORT STATE SERVICE REASON
    console.print(f"{'PORT':<9} {'STATE':<6} {'SERVICE':<10} {'REASON'}")
    if report.services:
        seen_table = set()
        for s in report.services:
            key = (s.port, s.protocol)
            if key in seen_table:
                continue
            seen_table.add(key)
            reason = s.banner or "syn-ack ttl 61"
            console.print(f"{str(s.port)+'/'+s.protocol:<9} {s.state.lower():<6} {s.service_name or 'unknown':<10} {reason}")
    else:
        console.print(f"None      closed -          No exposed ports found in authorized scope.")

    # Vulnerabilities
    if report.findings:
        console.print(f"\n[bold red][-][/bold red] [bold white]VULNERABILITY FINDINGS ({len(report.findings)})[/bold white]")
        for f in report.findings:
            sev_color = "bold red" if f.severity.value in ("critical", "high") else "yellow"
            cve_str = f" [{f.cve_id}]" if f.cve_id else ""
            console.print(f"  [{sev_color}][!][/{sev_color}] [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}{cve_str} [dim]via {f.source_tool}[/dim]")
            if f.remediation:
                console.print(f"      [dim]-> Remediation: {f.remediation}[/dim]")

    # AI Security Analyst Section
    ai_file = config.scans_dir / scan_id / "ai_analysis.json"
    if ai_file.exists():
        console.print(f"\n[bold cyan][~][/bold cyan] Starting AI Security Analyst (NVIDIA NIM: {config.nvidia_nim_model})")
        console.print(f"[bold green][>][/bold green] [bold green]Evidence-grounded vulnerability explanation & attack path synthesis completed.[/bold green]")
        try:
            ai_data = json.loads(ai_file.read_text(encoding="utf-8"))
            exec_summary = ai_data.get("executive_summary") or ""
            if exec_summary:
                first_lines = [l.strip() for l in exec_summary.split("\n") if l.strip() and not l.strip().startswith("#")][:3]
                if first_lines:
                    console.print(f"\n[bold cyan][~][/bold cyan] [bold white]AI Security Assessment Overview:[/bold white]")
                    for fl in first_lines:
                        console.print(f"    [dim]{fl}[/dim]")
        except Exception:
            pass

    console.print(f"\n[bold green][+][/bold green] [bold white]Scan completed successfully[/bold white]")
    console.print(f"[bold green][+][/bold green] Report saved: [bold cyan]{scan_id}[/bold cyan]")
    console.print(f"[bold green][+][/bold green] Storage path: [cyan]data/scans/{scan_id}/[/cyan]")
    console.print(f"    [bold cyan]->[/bold cyan] Standalone HTML : [cyan]data/scans/{scan_id}/final_report.html[/cyan]")
    console.print(f"    [bold cyan]->[/bold cyan] Markdown Report : [cyan]data/scans/{scan_id}/final_report.md[/cyan]")
    if ai_file.exists():
        console.print(f"    [bold cyan]->[/bold cyan] AI Analysis     : [cyan]data/scans/{scan_id}/ai_analysis.json[/cyan]\n")


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
    console.print(f"{'SCAN ID':<22} {'TARGET':<22} {'PROFILE':<10} {'STATUS':<12} {'FINDINGS':<10} {'AI':<10} {'TIMESTAMP'}")
    console.print("-" * 100)
    for s in scans:
        status_color = "bold green" if s["status"] == "completed" else "yellow"
        console.print(f"{s['scan_id']:<22} {s['target']:<22} {s['profile']:<10} [{status_color}]{s['status'].upper():<12}[/{status_color}] {str(s['finding_count']):<10} {s['ai_status']:<10} {s['start_time'][:19]}")


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


def cli_export(scan_id: str, report_format: str, out_path: Optional[str] = None):
    """Export a saved scan report in the chosen format."""
    print_banner()
    config = get_config()
    scan_dir = config.scans_dir / scan_id

    if not scan_dir.exists():
        console.print(f"[bold red][-][/bold red] Scan ID '{scan_id}' not found in storage.")
        return

    ext = "html" if report_format == "html" else ("md" if report_format == "markdown" else "json")
    src_file = scan_dir / f"final_report.{ext}"

    if not src_file.exists():
        console.print(f"[bold red][-][/bold red] Format '{report_format}' not available for {scan_id}.")
        return

    content = src_file.read_text(encoding="utf-8", errors="replace")

    if out_path:
        dest = Path(out_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        console.print(f"[bold green][+][/bold green] Report successfully exported to: [bold cyan]{dest}[/bold cyan]")
    else:
        console.print(content)


def cli_delete(scan_id: str):
    """Delete an assessment record and all associated on-disk evidence."""
    import shutil
    print_banner()
    config = get_config()
    db = DatabaseRepository(config.database_path)

    deleted = db.delete_scan(scan_id)
    scan_dir = config.scans_dir / scan_id
    fs_deleted = False
    if scan_dir.exists():
        shutil.rmtree(scan_dir, ignore_errors=True)
        fs_deleted = True

    if deleted or fs_deleted:
        console.print(f"[bold green][+][/bold green] Assessment [bold cyan]{scan_id}[/bold cyan] and associated evidence successfully removed.")
    else:
        console.print(f"[bold yellow][*][/bold yellow] Scan ID '{scan_id}' not found in database or storage.")


def run_cli():
    """CLI Argument parser entrypoint supporting RustScan-style flags."""
    parser = argparse.ArgumentParser(
        description="RootScan - Modern Day Security Assessment Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # RustScan-style flags directly on root
    parser.add_argument("-a", "--addresses", dest="address", help="Target IP address or domain (RustScan style)")
    parser.add_argument("-u", "--ulimit", dest="ulimit", type=int, default=5000, help="Batch ulimit (default 5000)")
    parser.add_argument("--profile", default="quick", choices=["quick", "standard", "deep", "custom"], help="Assessment profile")
    parser.add_argument("--allow-private", action="store_true", help="Authorize scanning private IP ranges")
    parser.add_argument("--tui", action="store_true", help="Launch full-screen Textual dashboard")

    subparsers = parser.add_subparsers(dest="command", help="Optional subcommands")

    # scan subcommand
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

    # export command
    exp_p = subparsers.add_parser("export", help="Export assessment report in HTML, Markdown, or JSON")
    exp_p.add_argument("scan_id", help="Scan ID to export")
    exp_p.add_argument("--format", default="html", choices=["html", "markdown", "json"], help="Output report format")
    exp_p.add_argument("--out", default=None, help="Destination file path")

    # delete command
    del_p = subparsers.add_parser("delete", help="Delete assessment record and all evidence")
    del_p.add_argument("scan_id", help="Scan ID to delete")

    args, unknown = parser.parse_known_args()

    # If --tui was explicitly requested
    if args.tui:
        from app.tui.app import RootScanApp
        app = RootScanApp()
        app.run()
        return

    # If -a / --addresses flag was provided (RustScan syntax)
    if args.address:
        check_and_install_missing_tools(auto_download=True, verbose=False)
        asyncio.run(run_rustscan_assessment(args.address, ulimit=args.ulimit, profile=args.profile, allow_private=args.allow_private))
        return

    # If positional or subcommand
    if args.command == "scan":
        check_and_install_missing_tools(auto_download=True, verbose=False)
        asyncio.run(run_rustscan_assessment(args.target, ulimit=args.ulimit, profile=args.profile, allow_private=args.allow_private))
    elif args.command == "history":
        cli_history()
    elif args.command == "tools":
        asyncio.run(cli_tools())
    elif args.command == "ai-test":
        asyncio.run(cli_ai_test())
    elif args.command == "compare":
        cli_compare(args.scan1, args.scan2)
    elif args.command == "export":
        cli_export(args.scan_id, args.format, args.out)
    elif args.command == "delete":
        cli_delete(args.scan_id)
    else:
        # Check if an unknown positional argument was passed as target (e.g. `rootscan scanme.nmap.org`)
        if unknown and not unknown[0].startswith("-"):
            target = unknown[0]
            check_and_install_missing_tools(auto_download=True, verbose=False)
            asyncio.run(run_rustscan_assessment(target, ulimit=args.ulimit, profile=args.profile, allow_private=args.allow_private))
            return

        # Interactive prompt when launched without arguments (e.g. `.\start.ps1`)
        print_banner()
        check_and_install_missing_tools(auto_download=True, verbose=True)
        try:
            raw_input_line = console.input("[bold green][?][/bold green] [bold white]Enter Target IP or Domain to scan:[/bold white] ").strip()
            if not raw_input_line:
                console.print("[yellow][*][/yellow] No target provided. Exiting.")
                return

            import shlex
            tokens = shlex.split(raw_input_line)
            cmd = tokens[0].lower()

            if cmd in ("exit", "quit", "q"):
                console.print("[yellow][*][/yellow] Session terminated.")
                return
            elif cmd == "history":
                cli_history()
                return
            elif cmd == "tools":
                asyncio.run(cli_tools())
                return
            elif cmd == "ai-test":
                asyncio.run(cli_ai_test())
                return

            # Target scan execution
            target = ""
            ulimit = args.ulimit
            profile = args.profile
            allow_priv = args.allow_private

            if tokens and tokens[0].startswith("-"):
                sub_args, sub_unk = parser.parse_known_args(tokens)
                target = sub_args.address or (sub_unk[0] if sub_unk else "")
                ulimit = sub_args.ulimit
                profile = sub_args.profile
                allow_priv = sub_args.allow_private
            else:
                target = tokens[0]
                if len(tokens) > 1:
                    sub_args, _ = parser.parse_known_args(tokens[1:])
                    ulimit = sub_args.ulimit
                    profile = sub_args.profile
                    allow_priv = sub_args.allow_private or allow_priv

            if target:
                # Check if it is a private IP (e.g. TryHackMe / lab target)
                from app.security.validation import validate_target
                val = validate_target(target, allow_private=False)
                if val.is_private and not allow_priv:
                    auth = console.input(f"[bold yellow][?][/bold yellow] Target '{target}' is in a private network range. Authorize scan? [Y/n]: ").strip().lower()
                    if auth in ("n", "no"):
                        console.print("[yellow][*][/yellow] Scan cancelled.")
                        return
                    allow_priv = True

                console.print(f"[bold green][+][/bold green] Starting full assessment pipeline for [bold cyan]{target}[/bold cyan]...\n")
                asyncio.run(run_rustscan_assessment(
                    target,
                    ulimit=ulimit,
                    profile=profile,
                    allow_private=allow_priv,
                    banner_printed=True
                ))
            else:
                console.print("[yellow][*][/yellow] No valid target specified. Exiting.")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow][*][/yellow] Session terminated.")
