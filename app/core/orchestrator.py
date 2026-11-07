"""Core 7-stage scanning pipeline orchestrator for RootScan."""

from __future__ import annotations

import asyncio
from datetime import datetime
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from app.ai.nim_client import NimClient
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
    Confidence,
    FinalReport,
    NormalizedFinding,
    PortResult,
    PortState,
    ScanMetadata,
    ServiceResult,
    Severity,
    TargetModel,
)
from app.reports.storage import ReportStorage, generate_scan_id
from app.scanners.httpx import HttpxAdapter
from app.scanners.nikto import NiktoAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter
from app.scanners.rustscan import RustScanAdapter
from app.scanners.whatweb import WhatWebAdapter
from app.security.validation import TargetType, validate_target


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
        Execute full assessment pipeline for an authorized target.
        Returns: (success: bool, scan_id: Optional[str], final_report: Optional[FinalReport])
        """
        config = get_config()
        profile = config.get_profile(profile_name) or config.get_profile("quick")
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

        target_model = TargetModel(
            raw_input=raw_target,
            normalized_target=scope.target,
            target_type=scope.target_type,
            resolved_ips=list(scope.authorized_ips),
            is_private=scope.allow_private
        )
        self.storage.save_stage_json(scan_id, "target.json", target_model.model_dump())

        # Register scan in SQLite database
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
            resolved_ips=list(scope.authorized_ips)
        )

        evidence_dir = self.storage.get_evidence_dir(scan_id)
        ports: List[PortResult] = []
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
                recon_data["dns"] = await DnsIntelligence.gather(scope.target)
            elif scope.authorized_ips:
                first_ip = next(iter(scope.authorized_ips))
                recon_data["ip"] = await IpIntelligence.gather(first_ip)
            self.storage.save_stage_json(scan_id, "reconnaissance.json", recon_data)
        except Exception as e:
            recon_data["error"] = str(e)

        # --- STAGE 3 & 4: PORT DISCOVERY & SERVICE ENUMERATION ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="port_discovery",
            message="Discovering open ports and fingerprinting services."
        ))

        nmap_adapter = NmapAdapter(task_manager=self.task_manager)
        if nmap_adapter.is_available:
            try:
                nmap_ports, nmap_services, nmap_findings = await nmap_adapter.run_discovery(
                    scan_id=scan_id,
                    target=scope.target,
                    options=profile,
                    evidence_dir=evidence_dir,
                    timeout_seconds=profile.get("timeout_seconds", 300)
                )
                ports.extend(nmap_ports)
                services.extend(nmap_services)
                findings.extend(nmap_findings)
                tool_summary["Nmap"] = f"Discovered {len(nmap_ports)} ports, {len(nmap_services)} services"
            except Exception as e:
                tool_summary["Nmap"] = f"Execution error: {e}"
        else:
            # Fallback simulated discovery if external tools are not yet installed in host environment
            tool_summary["Nmap"] = "Skipped (Binary not installed)"
            skipped_stages.append("nmap_scanning")

        # Probing Web Services with httpx if available
        httpx_adapter = HttpxAdapter(task_manager=self.task_manager)
        if httpx_adapter.is_available:
            try:
                web_services = await httpx_adapter.probe(
                    scan_id=scan_id,
                    target=scope.target,
                    options=profile,
                    evidence_dir=evidence_dir
                )
                services.extend(web_services)
                tool_summary["httpx"] = f"Probed {len(web_services)} web endpoints"
            except Exception as e:
                tool_summary["httpx"] = f"Error: {e}"

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

        # --- STAGE 5 & 6: CONDITIONAL VULNERABILITY ASSESSMENT ---
        await self.event_bus.publish(ScanEvent(
            event_type=EventType.STAGE_STARTED,
            scan_id=scan_id,
            stage_name="vulnerability_assessment",
            message="Executing vulnerability checks within authorized boundaries."
        ))

        nuclei_adapter = NucleiAdapter(task_manager=self.task_manager)
        if nuclei_adapter.is_available:
            try:
                res, nuclei_findings = await nuclei_adapter.execute(
                    scan_id=scan_id,
                    target=scope.target,
                    options=profile,
                    evidence_dir=evidence_dir,
                    timeout_seconds=profile.get("timeout_seconds", 600)
                )
                findings.extend(nuclei_findings)
                tool_summary["Nuclei"] = f"Identified {len(nuclei_findings)} security findings"
            except Exception as e:
                tool_summary["Nuclei"] = f"Execution error: {e}"
        else:
            tool_summary["Nuclei"] = "Skipped (Binary not installed)"
            skipped_stages.append("nuclei_vulnerability_scan")

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

        # Write JSON and Markdown reports
        self.storage.save_stage_json(scan_id, "final_report.json", final_report.model_dump())
        md_content = ReportGenerator.generate_markdown(final_report)
        self.storage.save_markdown_report(scan_id, md_content)

        # Update DB status
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
                ai_analysis = await self.nim_client.analyze_scan_report(final_report)
                if ai_analysis:
                    self.storage.save_stage_json(scan_id, "ai_analysis.json", ai_analysis.model_dump())
                    self.db.save_ai_analysis(
                        scan_id=scan_id,
                        model=ai_analysis.model,
                        executive_summary=ai_analysis.executive_summary,
                        attack_surface_analysis=ai_analysis.attack_surface_analysis,
                        vulnerability_explanation=ai_analysis.vulnerability_explanation,
                        exploit_intelligence=ai_analysis.exploit_intelligence,
                        attack_path_analysis=ai_analysis.attack_path_analysis,
                        recommendations=ai_analysis.recommendations,
                        full_analysis_json=json.dumps(ai_analysis.model_dump())
                    )
                    self.db.update_scan_status(scan_id=scan_id, status="completed", ai_status="completed")
            except Exception as e:
                self.db.update_scan_status(scan_id=scan_id, status="completed", ai_status="failed")
        else:
            self.db.update_scan_status(scan_id=scan_id, status="completed", ai_status="skipped")

        # Generate standalone HTML report
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

