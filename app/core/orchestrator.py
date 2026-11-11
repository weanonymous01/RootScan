"""Core 7-stage scanning pipeline orchestrator for RootScan."""

from __future__ import annotations

import asyncio
from datetime import datetime
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from app.ai.nim_client import NimClient
from app.ai.report_analyzer import ReportAnalyzer
from app.core.configuration import get_config
from app.core.event_bus import EventType, ScanEvent, get_event_bus
from app.core.scope_manager import ScopeManager
from app.core.task_manager import TaskManager
from app.database.models import FindingRecord, ScanRecord, ServiceRecord
from app.database.repository import DatabaseRepository
from app.intelligence.correlation import FindingCorrelator
from app.intelligence.dns_intelligence import DnsIntelligence
from app.intelligence.ip_intelligence import IpIntelligence
from app.reports.generator import ReportGenerator
from app.reports.html_exporter import HtmlReportExporter
from app.reports.schemas import (
    FinalReport,
    NormalizedFinding,
    PortResult,
    ScanMetadata,
    ServiceResult,
    TargetModel,
)
from app.reports.storage import ReportStorage, generate_scan_id
from app.scanners.banner_probe import BannerProbe
from app.scanners.httpx import HttpxAdapter
from app.scanners.naabu import NaabuAdapter
from app.scanners.nikto import NiktoAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter
from app.scanners.rustscan import RustScanAdapter
from app.scanners.whatweb import WhatWebAdapter
from app.security.validation import TargetType


COMMON_PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9000}


def _merge_port_into(port_map: Dict[Tuple[int, str], PortResult], candidate: PortResult) -> bool:
    """Merge discovered port into port_map, combining source attribution. Returns True if newly discovered."""
    key = (candidate.port, candidate.protocol)
    existing = port_map.get(key)
    if not existing:
        if candidate.discovery_source and candidate.discovery_source not in candidate.source_tools:
            candidate.source_tools = candidate.all_sources()
        port_map[key] = candidate
        return True

    combined = existing.all_sources()
    for src in candidate.all_sources():
        if src not in combined:
            combined.append(src)
    existing.source_tools = combined
    existing.discovery_source = ", ".join(combined)
    return False


def _merge_service_into(services: List[ServiceResult], incoming: ServiceResult, prefer_service_fields: bool = True) -> None:
    """Merge service metadata into services list by (port, protocol), preserving all tool attributions."""
    for existing in services:
        if existing.port == incoming.port and existing.protocol == incoming.protocol:
            if prefer_service_fields:
                if incoming.service_name and (not existing.service_name or existing.service_name == "unknown" or incoming.source_tool in ("httpx", "Nmap")):
                    existing.service_name = incoming.service_name
                if incoming.service_version:
                    existing.service_version = incoming.service_version
                if incoming.banner:
                    if existing.banner and incoming.banner not in existing.banner:
                        existing.banner = f"{existing.banner} | {incoming.banner}"
                    elif not existing.banner:
                        existing.banner = incoming.banner
            else:
                if not existing.service_name or existing.service_name == "unknown":
                    existing.service_name = incoming.service_name
                if not existing.service_version and incoming.service_version:
                    existing.service_version = incoming.service_version
                if incoming.banner:
                    if existing.banner and incoming.banner not in existing.banner:
                        existing.banner = f"{existing.banner} | {incoming.banner}"
                    elif not existing.banner:
                        existing.banner = incoming.banner

            if incoming.technologies:
                merged_tech = list(existing.technologies)
                for t in incoming.technologies:
                    if t not in merged_tech:
                        merged_tech.append(t)
                existing.technologies = merged_tech

            combined = existing.all_sources()
            for src in incoming.all_sources():
                if src not in combined:
                    combined.append(src)
            existing.source_tools = combined
            existing.source_tool = ", ".join(combined)
            return

    incoming.source_tools = incoming.all_sources()
    if incoming.source_tools:
        incoming.source_tool = ", ".join(incoming.source_tools)
    services.append(incoming)


def _format_web_url(scheme: str, target: str, port: int) -> str:
    """Format canonical HTTP/HTTPS URL omitting default ports 80 and 443."""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{target}"
    return f"{scheme}://{target}:{port}"


def _build_web_urls(target: str, services: List[ServiceResult], ports: List[PortResult]) -> List[str]:
    """Build explicit HTTP/HTTPS target URLs for discovered web services and ports."""
    if target.startswith(("http://", "https://")):
        return [target]

    urls: List[str] = []
    seen_ports: set[int] = set()

    for s in services:
        is_web = (s.service_name in ("http", "https", "http-alt", "http-proxy", "https-alt")) or (s.port in WEB_PORTS)
        if is_web and s.port not in seen_ports:
            seen_ports.add(s.port)
            scheme = "https" if (s.port in (443, 8443) or "https" in (s.service_name or "")) else "http"
            urls.append(_format_web_url(scheme, target, s.port))

    for p in ports:
        if p.port in WEB_PORTS and p.port not in seen_ports:
            seen_ports.add(p.port)
            scheme = "https" if p.port in (443, 8443) else "http"
            urls.append(_format_web_url(scheme, target, p.port))

    return urls


class ScanOrchestrator:
    """Coordinates and executes the automated RootScan assessment workflow."""

    def __init__(
        self,
        db: Optional[DatabaseRepository] = None,
        storage: Optional[ReportStorage] = None,
        task_manager: Optional[TaskManager] = None
    ):
        config = get_config()
        self.db = db or DatabaseRepository(config.database_path)
        self.storage = storage or ReportStorage(config.scans_dir)
        self.task_manager = task_manager or TaskManager()
        self.event_bus = get_event_bus()
        self.scope_manager = ScopeManager(allow_private_default=config.allow_private_ranges)
        self.nim_client = NimClient()
        self.is_cancelled = False

    async def execute_scan(
        self,
        raw_target: str,
        profile_name: str = "quick",
        allow_private: bool = False
    ) -> tuple[bool, Optional[str], Optional[FinalReport]]:
        """
        Execute full multi-tool assessment pipeline for an authorized target.
        Every discovered datum is attributed to the tool(s) that produced it.
        """
        config = get_config()
        profile = dict(config.get_profile(profile_name) or config.get_profile("quick"))
        profile["_profile_name"] = profile_name
        scan_id = generate_scan_id()
        start_time = datetime.utcnow()
        start_monotonic = time.monotonic()
        self.is_cancelled = False

        # --- STAGE 1: TARGET VALIDATION ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="target_validation",
            message="Validating target and verifying assessment authorization scope."
        ))

        is_authorized, scope, auth_msg = self.scope_manager.register_scope(
            raw_target=raw_target,
            allow_private=allow_private
        )

        if not is_authorized or not scope:
            err_msg = f"Target rejected during scope validation: {auth_msg}"
            await self.event_bus.publish(ScanEvent(
                event_type=EventType.STAGE_FAILED,
                scan_id=scan_id,
                stage_name="target_validation",
                message=err_msg
            ))
            return False, None, None

        resolved_ips = list(scope.authorized_ips)
        target_ip = resolved_ips[0] if resolved_ips else scope.target
        target_model = TargetModel(
            raw_input=raw_target,
            normalized_target=scope.target,
            target_type=scope.target_type,
            resolved_ips=resolved_ips,
            is_private=scope.allow_private
        )
        self.storage.save_stage_json(scan_id, "target.json", target_model.model_dump())

        self.db.create_scan(ScanRecord(
            scan_id=scan_id,
            target=scope.target,
            target_type=scope.target_type,
            profile=profile_name,
            status="running",
            start_time=start_time.isoformat()
        ))
        self.db.add_target(
            scan_id=scan_id,
            raw_input=raw_target,
            normalized_target=scope.target,
            target_type=scope.target_type,
            is_private=scope.allow_private,
            resolved_ips=resolved_ips
        )

        evidence_dir = self.storage.get_evidence_dir(scan_id)
        port_map: Dict[Tuple[int, str], PortResult] = {}
        services: List[ServiceResult] = []
        findings: List[NormalizedFinding] = []
        recon_data: Dict[str, Any] = {}
        tool_summary: Dict[str, Any] = {}
        skipped_stages: List[str] = []

        # --- STAGE 2: RECONNAISSANCE ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="reconnaissance",
            message="Gathering DNS and IP network intelligence."
        ))

        try:
            if scope.target_type == TargetType.DOMAIN.value:
                dns_res = await DnsIntelligence.gather(scope.target)
                recon_data["dns"] = dns_res
                rec_count = sum(
                    len(dns_res.get(k, []))
                    for k in ("a_records", "aaaa_records", "cname_records", "mx_records", "ns_records", "txt_records")
                )
                tool_summary["DnsIntelligence"] = f"Resolved {rec_count} DNS records for {scope.target}"

            if resolved_ips:
                ip_res = await IpIntelligence.gather(target_ip)
                recon_data["ip"] = ip_res
                rdap_name = (ip_res.get("rdap") or {}).get("name") or "No RDAP org"
                rdns = ip_res.get("reverse_dns") or "No PTR"
                tool_summary["IpIntelligence"] = f"rDNS={rdns}; RDAP={rdap_name}"

            self.storage.save_stage_json(scan_id, "reconnaissance.json", recon_data)
        except Exception as e:
            recon_data["error"] = str(e)

        # --- STAGE 3: MULTI-ENGINE PORT DISCOVERY (RustScan + Naabu + Nmap) ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="port_discovery",
            message="Running multi-tool open port discovery."
        ))

        # 3A: RustScan (binary preferred, socket fallback if binary unavailable)
        rustscan_adapter = RustScanAdapter(task_manager=self.task_manager)
        if rustscan_adapter.is_available:
            try:
                rs_ports = await rustscan_adapter.scan_ports(
                    scan_id=scan_id,
                    target=scope.target,
                    options=profile,
                    evidence_dir=evidence_dir,
                    timeout_seconds=90
                )
                for p in rs_ports:
                    if _merge_port_into(port_map, p):
                        await self.event_bus.publish(ScanEvent(
                            event_type=EventType.PORT_DISCOVERED,
                            scan_id=scan_id,
                            tool_name="RustScan",
                            data={"port": p.port, "ip": target_ip, "tool": "RustScan"},
                            message=f"Open {target_ip}:{p.port}"
                        ))
                tool_summary["RustScan"] = f"Discovered {len(rs_ports)} open port(s)"
            except Exception as e:
                tool_summary["RustScan"] = f"Execution error: {e}"
        else:
            fb_ports = await RustScanAdapter.fast_socket_discovery(scope.target)
            for p in fb_ports:
                if _merge_port_into(port_map, p):
                    await self.event_bus.publish(ScanEvent(
                        event_type=EventType.PORT_DISCOVERED,
                        scan_id=scan_id,
                        tool_name="RustScan-SocketFallback",
                        data={"port": p.port, "ip": target_ip, "tool": "RustScan-SocketFallback"},
                        message=f"Open {target_ip}:{p.port}"
                    ))
            tool_summary["RustScan-SocketFallback"] = f"Discovered {len(fb_ports)} open port(s) (binary fallback)"

        # 3B: Naabu cross-verification port discovery
        naabu_adapter = NaabuAdapter(task_manager=self.task_manager)
        if naabu_adapter.is_available:
            try:
                nb_ports = await naabu_adapter.scan_ports(
                    scan_id=scan_id,
                    target=scope.target,
                    options=profile,
                    evidence_dir=evidence_dir,
                    timeout_seconds=60
                )
                new_by_naabu = 0
                for p in nb_ports:
                    if _merge_port_into(port_map, p):
                        new_by_naabu += 1
                        await self.event_bus.publish(ScanEvent(
                            event_type=EventType.PORT_DISCOVERED,
                            scan_id=scan_id,
                            tool_name="Naabu",
                            data={"port": p.port, "ip": target_ip, "tool": "Naabu"},
                            message=f"Open {target_ip}:{p.port}"
                        ))
                tool_summary["Naabu"] = f"Discovered {len(nb_ports)} open port(s) ({new_by_naabu} additional)"
            except Exception as e:
                tool_summary["Naabu"] = f"Execution error: {e}"
        else:
            tool_summary["Naabu"] = "Skipped (binary not installed)"

        ports: List[PortResult] = sorted(port_map.values(), key=lambda x: x.port)

        # Seed initial service entries preserving port discovery source tools
        for p in ports:
            svc_name = COMMON_PORT_NAMES.get(p.port, "unknown")
            services.append(ServiceResult(
                port=p.port,
                protocol=p.protocol,
                state=p.state.value,
                service_name=svc_name,
                source_tool=p.discovery_source,
                source_tools=p.all_sources()
            ))

        # 3C: Nmap deep service/script discovery (when Nmap binary is available)
        nmap_adapter = NmapAdapter(task_manager=self.task_manager)
        if nmap_adapter.is_available:
            try:
                nmap_opts = dict(profile)
                if ports:
                    nmap_opts["port_range"] = ",".join(str(p.port) for p in ports)
                nmap_ports, nmap_services, nmap_findings = await nmap_adapter.run_discovery(
                    scan_id=scan_id,
                    target=scope.target,
                    options=nmap_opts,
                    evidence_dir=evidence_dir,
                    timeout_seconds=profile.get("timeout_seconds", 300)
                )
                for p in nmap_ports:
                    if _merge_port_into(port_map, p):
                        await self.event_bus.publish(ScanEvent(
                            event_type=EventType.PORT_DISCOVERED,
                            scan_id=scan_id,
                            tool_name="Nmap",
                            data={"port": p.port, "ip": target_ip, "tool": "Nmap"},
                            message=f"Open {target_ip}:{p.port}"
                        ))
                ports = sorted(port_map.values(), key=lambda x: x.port)
                for ns in nmap_services:
                    _merge_service_into(services, ns, prefer_service_fields=True)
                findings.extend(nmap_findings)
                tool_summary["Nmap"] = f"Fingerprinted {len(nmap_services)} service(s), {len(nmap_findings)} NSE finding(s)"
            except Exception as e:
                tool_summary["Nmap"] = f"Execution error: {e}"
        else:
            tool_summary["Nmap"] = "Skipped (binary not installed; covered by RustScan, Naabu, httpx, SocketBanner/TLSProbe)"
            skipped_stages.append("nmap_service_scan")

        # --- STAGE 4: SERVICE ENUMERATION (httpx + WhatWeb + SocketBanner/TLSProbe) ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="service_enumeration",
            message="Fingerprinting web endpoints, TLS certificates, and service banners."
        ))

        candidate_web_ports = [p.port for p in ports if p.port in WEB_PORTS] or [80, 443]
        httpx_adapter = HttpxAdapter(task_manager=self.task_manager)
        if httpx_adapter.is_available:
            try:
                web_services = await httpx_adapter.probe(
                    scan_id=scan_id,
                    target=scope.target,
                    options=profile,
                    evidence_dir=evidence_dir,
                    candidate_ports=candidate_web_ports
                )
                for ws in web_services:
                    _merge_service_into(services, ws, prefer_service_fields=True)
                tool_summary["httpx"] = f"Probed {len(web_services)} web endpoint(s)"
            except Exception as e:
                tool_summary["httpx"] = f"Execution error: {e}"
        else:
            try:
                web_services = await HttpxAdapter.python_fallback_probe(scope.target, candidate_web_ports)
                for ws in web_services:
                    _merge_service_into(services, ws, prefer_service_fields=True)
                tool_summary["httpx"] = f"Built-in HTTP engine probed {len(web_services)} endpoint(s)"
            except Exception as e:
                tool_summary["httpx"] = f"Fallback error: {e}"

        # SocketBanner & TLSProbe inspection for non-HTTP services and TLS certificates
        if ports:
            try:
                probe_results = await BannerProbe.probe_services(
                    target=target_ip,
                    ports=[p.port for p in ports],
                    sni_host=scope.target
                )
                for pr in probe_results:
                    _merge_service_into(services, pr, prefer_service_fields=False)
                tool_summary["SocketBanner/TLSProbe"] = f"Inspected {len(probe_results)} banner/TLS endpoint(s)"
            except Exception as e:
                tool_summary["SocketBanner/TLSProbe"] = f"Probe error: {e}"

        web_urls = _build_web_urls(scope.target, services, ports)

        # WhatWeb technology fingerprinting (when installed, e.g. on Linux/Kali)
        whatweb_adapter = WhatWebAdapter(task_manager=self.task_manager)
        if whatweb_adapter.is_available and web_urls:
            try:
                ww_count = 0
                for idx, url in enumerate(web_urls[:3]):
                    res, _ = await whatweb_adapter.execute(
                        scan_id=scan_id,
                        target=url,
                        options=profile,
                        evidence_dir=evidence_dir,
                        timeout_seconds=45
                    )
                    json_ev = (evidence_dir / "whatweb_output.json")
                    raw_ww = json_ev.read_text(encoding="utf-8", errors="replace") if json_ev.exists() else res.stdout
                    for ww_svc in whatweb_adapter.parse_services(raw_ww):
                        _merge_service_into(services, ww_svc, prefer_service_fields=False)
                        ww_count += 1
                tool_summary["WhatWeb"] = f"Fingerprinted {ww_count} web service(s)"
            except Exception as e:
                tool_summary["WhatWeb"] = f"Execution error: {e}"
        else:
            tool_summary["WhatWeb"] = "Skipped (binary not installed; web tech fingerprinted by httpx)"

        services.sort(key=lambda x: x.port)

        # Save ports and services
        self.storage.save_stage_json(scan_id, "ports.json", [p.model_dump() for p in ports])
        self.storage.save_stage_json(scan_id, "services.json", [s.model_dump() for s in services])
        for s in services:
            self.db.add_service(ServiceRecord(
                scan_id=scan_id,
                port=s.port,
                protocol=s.protocol,
                state=s.state,
                service_name=s.service_name,
                service_version=s.service_version,
                banner=s.banner,
                tech_stack=json.dumps(s.technologies)
            ))

        # --- STAGE 5 & 6: CONDITIONAL VULNERABILITY ASSESSMENT (Nuclei + Nikto) ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="vulnerability_assessment",
            message="Executing vulnerability checks within authorized boundaries."
        ))

        scan_targets = web_urls or [scope.target]

        nuclei_adapter = NucleiAdapter(task_manager=self.task_manager)
        if nuclei_adapter.is_available:
            try:
                res, nuclei_findings = await nuclei_adapter.scan_targets(
                    scan_id=scan_id,
                    targets=scan_targets,
                    options=profile,
                    evidence_dir=evidence_dir,
                    timeout_seconds=min(profile.get("timeout_seconds", 300), 120)
                )
                findings.extend(nuclei_findings)
                tool_summary["Nuclei"] = f"Identified {len(nuclei_findings)} finding(s) across {len(scan_targets)} target(s)"
            except Exception as e:
                tool_summary["Nuclei"] = f"Execution error: {e}"
        else:
            tool_summary["Nuclei"] = "Skipped (binary not installed)"
            skipped_stages.append("nuclei_vulnerability_scan")

        nikto_adapter = NiktoAdapter(task_manager=self.task_manager)
        if nikto_adapter.is_available and web_urls:
            try:
                res, nikto_findings = await nikto_adapter.execute(
                    scan_id=scan_id,
                    target=web_urls[0],
                    options=profile,
                    evidence_dir=evidence_dir,
                    timeout_seconds=min(profile.get("timeout_seconds", 300), 120)
                )
                findings.extend(nikto_findings)
                tool_summary["Nikto"] = f"Identified {len(nikto_findings)} web finding(s)"
            except Exception as e:
                tool_summary["Nikto"] = f"Execution error: {e}"
        else:
            tool_summary["Nikto"] = "Skipped (binary not installed; covered by Nuclei)"

        # Deduplicate, correlate, and enrich findings
        unique_findings = FindingCorrelator.deduplicate_findings(findings)
        unique_findings = FindingCorrelator.link_findings_to_services(services, unique_findings)
        unique_findings = await FindingCorrelator.enrich_findings_with_cve_intelligence(unique_findings)

        for f in unique_findings:
            self.db.add_finding(FindingRecord(
                scan_id=scan_id,
                title=f.title,
                severity=f.severity.value,
                confidence=f.confidence.value,
                source_tool=f.source_tool,
                cve_id=f.cve_id,
                affected_component=f.affected_component,
                observed_version=f.observed_version,
                evidence_text=f.evidence,
                remediation=f.remediation
            ))

        self.storage.save_stage_json(scan_id, "vulnerabilities.json", [f.model_dump() for f in unique_findings])

        # --- STAGE 7: DATA NORMALIZATION & REPORT GENERATION ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="normalization",
            message="Consolidating evidence and compiling final reports."
        ))

        duration_sec = round(time.monotonic() - start_monotonic, 2)
        end_time = datetime.utcnow()

        final_report = FinalReport(
            metadata=ScanMetadata(
                scan_id=scan_id,
                target=scope.target,
                target_type=scope.target_type,
                profile=profile_name,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration_sec,
                status="completed"
            ),
            target=target_model,
            reconnaissance=recon_data,
            ports=ports,
            services=services,
            findings=unique_findings,
            tool_summary=tool_summary,
            skipped_stages=skipped_stages,
            limitations=[
                "Assessment executed non-destructively within strictly defined scope boundaries.",
                "Exploits were not executed; vulnerabilities require verification."
            ]
        )

        self.storage.save_stage_json(scan_id, "final_report.json", final_report.model_dump())
        md_content = ReportGenerator.generate_markdown(final_report)
        self.storage.save_markdown_report(scan_id, md_content)

        self.db.update_scan_status(
            scan_id=scan_id,
            status="completed",
            end_time=end_time.isoformat(),
            duration_seconds=duration_sec,
            finding_count=len(unique_findings)
        )

        # --- STAGE 8: NVIDIA NIM AI SECURITY ANALYSIS ---
        ai_analysis = None
        if self.nim_client.is_configured:
            await self.event_bus.publish(ScanEvent(
                event_type=EventType.STAGE_STARTED,
                scan_id=scan_id,
                stage_name="ai_analysis",
                message="Submitting assessment report to NVIDIA NIM Security Analyst."
            ))
            try:
                ai_analysis = await ReportAnalyzer(self.nim_client).analyze(final_report)
                if ai_analysis:
                    self.storage.save_stage_json(scan_id, "ai_analysis.json", json.loads(ai_analysis.model_dump_json()))
                    self.db.save_ai_analysis(
                        scan_id=scan_id,
                        model=ai_analysis.model,
                        executive_summary=ai_analysis.executive_summary,
                        attack_surface_analysis=ai_analysis.attack_surface_analysis,
                        vulnerability_explanation=ai_analysis.vulnerability_explanation,
                        exploit_intelligence=ai_analysis.exploit_intelligence,
                        attack_path_analysis=ai_analysis.attack_path_analysis,
                        recommendations=ai_analysis.recommendations,
                        full_analysis_json=ai_analysis.model_dump_json()
                    )
                    self.db.update_scan_status(scan_id=scan_id, status="completed", ai_status="completed")
                    tool_summary["NVIDIA NIM"] = f"Completed analysis ({ai_analysis.model})"
                else:
                    self.db.update_scan_status(scan_id=scan_id, status="completed", ai_status="failed")
                    tool_summary["NVIDIA NIM"] = f"Unavailable / timed out ({self.nim_client.model})"
            except Exception as e:
                self.db.update_scan_status(scan_id=scan_id, status="completed", ai_status="failed")
                tool_summary["NVIDIA NIM"] = f"Error ({type(e).__name__}: {e})"
        else:
            self.db.update_scan_status(scan_id=scan_id, status="completed", ai_status="skipped")
            tool_summary["NVIDIA NIM"] = "Skipped (API key not configured)"

        # Persist final tool summary updates & generate standalone HTML report
        final_report.tool_summary = tool_summary
        self.storage.save_stage_json(scan_id, "final_report.json", final_report.model_dump())
        self.storage.save_markdown_report(scan_id, ReportGenerator.generate_markdown(final_report))
        html_content = HtmlReportExporter.export(final_report, ai_analysis=ai_analysis)
        self.storage.save_html_report(scan_id, html_content)

        await self.event_bus.publish(ScanEvent(
            event_type=EventType.SCAN_COMPLETED,
            scan_id=scan_id,
            data={"duration": duration_sec, "findings": len(unique_findings)},
            message=f"Assessment {scan_id} finished successfully."
        ))

        return True, scan_id, final_report

    async def cancel_scan(self, scan_id: str) -> None:
        """Interrupt and terminate an active assessment."""
        self.is_cancelled = True
        await self.task_manager.cancel_all()
        self.db.update_scan_status(scan_id=scan_id, status="interrupted")
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.SCAN_INTERRUPTED,
            scan_id=scan_id,
            message=f"Scan {scan_id} was cancelled by user."
        ))
