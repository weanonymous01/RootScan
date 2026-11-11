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

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
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
: https://weanonymous.in                :
: https://github.com/weanonymous01      :
 --------------------------------------[/bold green]
[bold cyan]Elliot: Just a Tech.[/bold cyan]
"""


def print_banner():
    console.print(RUSTSCAN_BANNER)


def _build_table(title: str) -> Table:
    """Create a consistently styled Rich table for CLI outputs."""
    return Table(
        title=title,
        title_justify="left",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold cyan",
        show_lines=False,
        pad_edge=True,
    )


def _render_recon_output(recon: dict):
    """Display DNS and IP intelligence clearly quoted with source tools in a table."""
    if not recon:
        return

    dns_info = recon.get("dns")
    ip_info = recon.get("ip")
    if not dns_info and not ip_info:
        return

    table = _build_table("[bold white]RECONNAISSANCE & NETWORK INTELLIGENCE[/bold white]")
    table.add_column("Record", style="bold white", no_wrap=True)
    table.add_column("Details", style="white")
    table.add_column("Found By", style="bold cyan", no_wrap=True)

    if dns_info:
        src = escape(str(dns_info.get("source_tool", "DnsIntelligence")))
        table.add_row("Domain", f"[cyan]{escape(str(dns_info.get('domain') or ''))}[/cyan]", src)
        for key, label in [
            ("a_records", "A Records"),
            ("aaaa_records", "AAAA Records"),
            ("cname_records", "CNAME"),
            ("mx_records", "MX Records"),
            ("ns_records", "NS Records"),
            ("txt_records", "TXT Records"),
        ]:
            vals = dns_info.get(key) or []
            if vals:
                table.add_row(label, escape(", ".join(vals[:5])), src)

    if ip_info:
        src = escape(str(ip_info.get("source_tool", "IpIntelligence")))
        ip_addr = ip_info.get("ip_address")
        rdns = ip_info.get("reverse_dns")
        rdap = ip_info.get("rdap") or {}
        table.add_row("IP Address", f"[cyan]{escape(str(ip_addr or ''))}[/cyan]", src)
        if rdns:
            table.add_row("Reverse DNS", escape(str(rdns)), src)
        if rdap:
            net_name = rdap.get("name") or rdap.get("org") or rdap.get("handle") or "Unknown"
            country = rdap.get("country") or "-"
            cidr = rdap.get("cidr") or (
                f"{rdap.get('start_address')} - {rdap.get('end_address')}"
                if rdap.get("start_address") else "-"
            )
            table.add_row("RDAP Owner", f"{escape(str(net_name))} ({escape(str(country))})", src)
            table.add_row("Netblock", escape(str(cidr)), src)

    console.print()
    console.print(table)


async def run_rustscan_assessment(
    target: str,
    ulimit: int = 5000,
    profile: str = "quick",
    allow_private: bool = False,
    banner_printed: bool = False,
):
    """Execute multi-tool assessment pipeline with strict per-tool result attribution."""
    config = get_config()
    if not banner_printed:
        print_banner()

    console.print(f"[bold cyan][~][/bold cyan] Target: [cyan]{escape(target)}[/cyan] | Profile: [cyan]{escape(profile)}[/cyan] | Batch ulimit: {ulimit}")

    event_bus = get_event_bus()
    discovered_ports_set: set[int] = set()

    async def log_event(event: ScanEvent):
        if event.event_type == EventType.PORT_DISCOVERED:
            p_data = event.data or {}
            port = p_data.get("port")
            ip = p_data.get("ip", target)
            tool = p_data.get("tool") or event.tool_name or "Scanner"
            if port and port not in discovered_ports_set:
                discovered_ports_set.add(port)
                console.print(f"Open [medium_purple1]{escape(str(ip))}:{port}[/medium_purple1] [bold cyan]{escape(f'[via {tool}]')}[/bold cyan]")
        elif event.event_type == EventType.TOOL_STARTED:
            console.print(f"[bold cyan][~][/bold cyan] Running [bold white]{escape(event.tool_name or '')}[/bold white]...")
        elif event.event_type == EventType.TOOL_FAILED:
            msg = event.message or f"exited with code {(event.data or {}).get('exit_code', '?')}"
            console.print(f"[bold yellow][*][/bold yellow] [bold white]{escape(event.tool_name or '')}[/bold white]: [yellow]{escape(msg)}[/yellow]")

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

    # Ensure any remaining discovered ports not emitted via live event are printed with attribution
    for p in report.ports:
        if p.port not in discovered_ports_set:
            discovered_ports_set.add(p.port)
            console.print(f"Open [medium_purple1]{escape(resolved_ip)}:{p.port}[/medium_purple1] [bold cyan]{escape(f'[via {p.discovery_source}]')}[/bold cyan]")

    _render_recon_output(report.reconnaissance)

    duration = report.metadata.duration_seconds or 0.0
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    ports_table = _build_table(
        f"[bold white]DISCOVERED PORTS & SERVICES[/bold white] [dim]({escape(report.target.normalized_target)} [{escape(resolved_ip)}] | {now_str} | {duration:.2f}s)[/dim]"
    )
    ports_table.add_column("Port", style="medium_purple1", no_wrap=True)
    ports_table.add_column("State", style="bold green", no_wrap=True)
    ports_table.add_column("Service", style="bold white", no_wrap=True)
    ports_table.add_column("Details / Banner", style="white")
    ports_table.add_column("Found By", style="bold cyan", no_wrap=True)

    if report.services:
        seen_table = set()
        for s in report.services:
            key = (s.port, s.protocol)
            if key in seen_table:
                continue
            seen_table.add(key)

            details_parts = []
            if s.service_version and s.service_version not in (s.banner or ""):
                details_parts.append(s.service_version)
            if s.banner:
                details_parts.append(s.banner)
            if s.technologies:
                tech_str = ", ".join(t for t in s.technologies if t not in (s.banner or ""))
                if tech_str:
                    details_parts.append(f"Tech: {tech_str}")

            details = " | ".join(details_parts) if details_parts else "open tcp port"
            if len(details) > 100:
                details = details[:97] + "..."
            tools_label = ", ".join(s.all_sources()) or s.source_tool
            ports_table.add_row(
                f"{s.port}/{s.protocol}",
                s.state.lower(),
                escape(s.service_name or "unknown"),
                escape(details),
                escape(tools_label),
            )
    else:
        ports_table.add_row("None", "[dim]closed[/dim]", "-", "No exposed ports found in authorized scope.", "RustScan, Naabu")

    console.print()
    console.print(ports_table)

    # Vulnerability Findings attributed per tool
    if report.findings:
        findings_table = _build_table(
            f"[bold white]VULNERABILITY & CONFIGURATION FINDINGS ({len(report.findings)})[/bold white]"
        )
        findings_table.add_column("Severity", no_wrap=True)
        findings_table.add_column("Finding", style="bold white")
        findings_table.add_column("Port", style="cyan", no_wrap=True)
        findings_table.add_column("Matched At / Remediation", style="dim")
        findings_table.add_column("Found By", style="bold cyan", no_wrap=True)

        for f in report.findings:
            sev_val = f.severity.value.upper()
            sev_color = "bold red" if sev_val in ("CRITICAL", "HIGH") else ("yellow" if sev_val == "MEDIUM" else "cyan")
            title_txt = f"{f.title} [{f.cve_id}]" if f.cve_id else f.title
            port_txt = f"{f.port}/{f.protocol or 'tcp'}" if f.port else "-"

            note_parts = []
            if f.evidence:
                note_parts.append(f.evidence.splitlines()[0])
            if f.remediation:
                note_parts.append(f"Fix: {f.remediation.splitlines()[0]}")
            note_txt = " | ".join(note_parts) if note_parts else "-"

            findings_table.add_row(
                f"[{sev_color}]{sev_val}[/{sev_color}]",
                escape(title_txt),
                port_txt,
                escape(note_txt),
                escape(f.source_tool),
            )
        console.print()
        console.print(findings_table)
    else:
        console.print(f"\n[bold green][+][/bold green] [bold white]VULNERABILITY ASSESSMENT:[/bold white] No active vulnerabilities detected [bold cyan]{escape('[Checked by: Nuclei]')}[/bold cyan]")

    # Tool Execution Audit Summary
    if report.tool_summary:
        audit_table = _build_table("[bold white]TOOL EXECUTION AUDIT[/bold white]")
        audit_table.add_column("Tool", style="bold white", no_wrap=True)
        audit_table.add_column("Status", no_wrap=True)
        audit_table.add_column("Summary", style="white")

        for tool_name, summary in report.tool_summary.items():
            summary_str = str(summary)
            if summary_str.startswith(("Skipped", "Unavailable")):
                status_badge = "[bold yellow]SKIPPED[/bold yellow]"
            elif summary_str.startswith(("Execution error", "Fallback error", "Probe error", "Error")):
                status_badge = "[bold red]ERROR[/bold red]"
            else:
                status_badge = "[bold green]EXECUTED[/bold green]"
            audit_table.add_row(escape(tool_name), status_badge, escape(summary_str))

        console.print()
        console.print(audit_table)

    # AI Security Analyst Section
    ai_file = config.scans_dir / scan_id / "ai_analysis.json"
    if ai_file.exists():
        try:
            ai_data = json.loads(ai_file.read_text(encoding="utf-8"))
            exec_summary = ai_data.get("executive_summary") or ""
            if exec_summary:
                paragraphs = [p.strip() for p in exec_summary.split("\n\n") if p.strip()][:3]
                if paragraphs:
                    panel_body = "\n\n".join(escape(p) for p in paragraphs)
                    console.print()
                    console.print(
                        Panel(
                            panel_body,
                            title=f"[bold cyan]AI Security Assessment Overview {escape(f'[NVIDIA NIM: {config.nvidia_nim_model}]')}[/bold cyan]",
                            title_align="left",
                            box=box.ROUNDED,
                            border_style="cyan",
                        )
                    )
        except Exception:
            pass

    reports_table = _build_table(f"[bold green]ASSESSMENT COMPLETED — {escape(scan_id)}[/bold green]")
    reports_table.add_column("Artifact", style="bold white", no_wrap=True)
    reports_table.add_column("Location", style="cyan")
    reports_table.add_row("HTML Report", f"data/scans/{scan_id}/final_report.html")
    reports_table.add_row("Markdown Report", f"data/scans/{scan_id}/final_report.md")
    if ai_file.exists():
        reports_table.add_row("AI Analysis", f"data/scans/{scan_id}/ai_analysis.json")

    console.print()
    console.print(reports_table)
    console.print()


def cli_history():
    """List historical scans stored in SQLite."""
    print_banner()
    config = get_config()
    db = DatabaseRepository(config.database_path)
    scans = db.list_scans(limit=25)

    if not scans:
        console.print("[bold yellow][*][/bold yellow] No historical assessments found in repository.")
        return

    hist_table = _build_table("[bold white]ASSESSMENT LOG ARCHIVE[/bold white]")
    hist_table.add_column("Scan ID", style="bold cyan", no_wrap=True)
    hist_table.add_column("Target", style="white", min_width=14, no_wrap=True)
    hist_table.add_column("Profile", style="cyan")
    hist_table.add_column("Status")
    hist_table.add_column("Findings", justify="right")
    hist_table.add_column("AI")
    hist_table.add_column("Timestamp", style="dim", no_wrap=True)

    for s in scans:
        status_color = "bold green" if s["status"] == "completed" else "yellow"
        ts = str(s["start_time"])[:16].replace("T", " ")
        hist_table.add_row(
            escape(str(s["scan_id"])),
            escape(str(s["target"])),
            escape(str(s["profile"])),
            f"[{status_color}]{escape(str(s['status']).upper())}[/{status_color}]",
            str(s["finding_count"]),
            escape(str(s["ai_status"])),
            escape(ts),
        )
    console.print(hist_table)


async def cli_tools():
    """Check availability of registered tools."""
    print_banner()
    from app.core.tool_installer import get_current_os_and_arch
    os_name, arch = get_current_os_and_arch()

    tools_table = _build_table(
        f"[bold white]SECURITY SCANNER REGISTRY HEALTH CHECK[/bold white] [dim]({os_name.title()} {arch})[/dim]"
    )
    tools_table.add_column("Tool", style="bold white", no_wrap=True)
    tools_table.add_column("Status", no_wrap=True)
    tools_table.add_column("Version / Notes", style="dim")

    adapters = [
        RustScanAdapter(), NucleiAdapter(), HttpxAdapter(), NaabuAdapter(),
        NmapAdapter(), WhatWebAdapter(), NiktoAdapter()
    ]

    for adp in adapters:
        if adp.is_available:
            ver = await adp.get_version()
            tools_table.add_row(adp.name, "[bold green]INSTALLED[/bold green]", escape(ver[:50]))
        else:
            if os_name == "windows":
                if adp.name == "Nmap":
                    hint = "Optional: Port scanning accelerated by native RustScan engine; or 'winget install Insecure.Nmap'"
                else:
                    hint = "Optional: Web scanning covered by native HTTPX & Nuclei engines"
            else:
                hint = f"Optional: install via 'sudo apt install {adp.binary_name}'"
            tools_table.add_row(adp.name, "[yellow]NOT FOUND[/yellow]", escape(hint))

    console.print(tools_table)


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
