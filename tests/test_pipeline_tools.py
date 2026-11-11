import asyncio
from datetime import datetime, timezone
import json

from app.ai.nim_client import build_ai_report_model, format_three_paragraph_summary
from app.core.orchestrator import _build_web_urls, _merge_port_into, _merge_service_into
from app.intelligence.correlation import FindingCorrelator
from app.parsers.nuclei_parser import NucleiParser
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
from app.scanners.banner_probe import BannerProbe
from app.scanners.httpx import HttpxAdapter
from app.scanners.naabu import NaabuAdapter
from app.scanners.rustscan import RustScanAdapter


class TestPipelineToolsAndAttribution:
    def test_port_and_service_all_sources_deduplicate(self):
        port = PortResult(
            port=443,
            discovery_source="RustScan",
            source_tools=["RustScan", "Naabu", "RustScan"],
        )
        assert port.all_sources() == ["RustScan", "Naabu"]

        service = ServiceResult(
            port=443,
            service_name="https",
            source_tool="httpx",
            source_tools=["httpx", "TLSProbe", "httpx"],
        )
        assert service.all_sources() == ["httpx", "TLSProbe"]

    def test_merge_port_and_service_attribution(self):
        port_map = {}
        first_new = _merge_port_into(
            port_map,
            PortResult(port=80, discovery_source="RustScan", source_tools=["RustScan"]),
        )
        second_new = _merge_port_into(
            port_map,
            PortResult(port=80, discovery_source="Naabu", source_tools=["Naabu"]),
        )
        assert first_new is True
        assert second_new is False
        merged_port = port_map[(80, "tcp")]
        assert merged_port.all_sources() == ["RustScan", "Naabu"]
        assert merged_port.discovery_source == "RustScan, Naabu"

        services = []
        _merge_service_into(
            services,
            ServiceResult(
                port=80,
                service_name="unknown",
                banner=None,
                source_tool="RustScan",
                source_tools=["RustScan"],
            ),
        )
        _merge_service_into(
            services,
            ServiceResult(
                port=80,
                service_name="http",
                service_version="nginx/1.24",
                banner="Server: nginx | HTTP 200",
                technologies=["nginx"],
                source_tool="httpx",
                source_tools=["httpx"],
            ),
        )
        assert len(services) == 1
        svc = services[0]
        assert svc.service_name == "http"
        assert svc.service_version == "nginx/1.24"
        assert svc.technologies == ["nginx"]
        assert svc.all_sources() == ["RustScan", "httpx"]
        assert svc.source_tool == "RustScan, httpx"

    def test_build_web_urls(self):
        ports = [
            PortResult(port=22, discovery_source="Naabu"),
            PortResult(port=80, discovery_source="RustScan"),
            PortResult(port=443, discovery_source="RustScan"),
            PortResult(port=8080, discovery_source="Naabu"),
        ]
        services = [
            ServiceResult(port=80, service_name="http", source_tool="httpx"),
            ServiceResult(port=443, service_name="https", source_tool="httpx"),
        ]
        urls = _build_web_urls("example.com", services, ports)
        assert urls == [
            "http://example.com",
            "https://example.com",
            "http://example.com:8080",
        ]

        fallback_urls = _build_web_urls("57.144.40.1", [], ports)
        assert fallback_urls == [
            "http://57.144.40.1",
            "https://57.144.40.1",
            "http://57.144.40.1:8080",
        ]

        assert _build_web_urls("https://example.com:8443", services, ports) == [
            "https://example.com:8443"
        ]

    def test_rustscan_and_naabu_parse_ports(self):
        rustscan = RustScanAdapter()
        rs_output = "\n".join(
            [
                "Open 57.144.40.1:80",
                "Open 57.144.40.1:443",
                "57.144.40.1 -> [80, 443, 8080]",
            ]
        )
        rs_ports = rustscan.parse_ports(rs_output)
        assert [p.port for p in rs_ports] == [80, 443, 8080]
        assert all(p.discovery_source == "RustScan" for p in rs_ports)
        assert all(p.source_tools == ["RustScan"] for p in rs_ports)

        naabu = NaabuAdapter()
        nb_output = "\n".join(
            [
                '{"host":"57.144.40.1","ip":"57.144.40.1","port":443,"protocol":"tcp"}',
                '{"host":"57.144.40.1","ip":"57.144.40.1","port":80,"protocol":"tcp"}',
                '{"host":"57.144.40.1","ip":"57.144.40.1","port":80,"protocol":"tcp"}',
                "not-json-line",
            ]
        )
        nb_ports = naabu.parse_ports(nb_output)
        assert [p.port for p in nb_ports] == [80, 443]
        assert all(p.discovery_source == "Naabu" for p in nb_ports)
        assert all(p.source_tools == ["Naabu"] for p in nb_ports)

    def test_httpx_build_candidate_urls(self):
        assert HttpxAdapter.build_candidate_urls("57.144.40.1", [80, 443, 8443, 22]) == [
            "http://57.144.40.1:80",
            "https://57.144.40.1:443",
            "https://57.144.40.1:8443",
        ]
        assert HttpxAdapter.build_candidate_urls("https://target.local") == [
            "https://target.local"
        ]

    def test_nuclei_parser_extracts_matcher_port_and_template(self):
        jsonl = json.dumps(
            {
                "template-id": "weak-cipher-suites",
                "matcher-name": "tls-1.1",
                "port": "443",
                "matched-at": "57.144.40.1:443",
                "info": {
                    "name": "Weak Cipher Suites Detection",
                    "severity": "medium",
                    "description": "Server supports weak cipher suites.",
                },
            }
        )
        findings = NucleiParser.parse_jsonl(jsonl)
        assert len(findings) == 1
        f = findings[0]
        assert f.title == "Weak Cipher Suites Detection (tls-1.1)"
        assert f.port == 443
        assert f.protocol == "tcp"
        assert f.source_tool == "Nuclei"
        assert "Template: weak-cipher-suites" in f.evidence

    def test_correlation_deduplicate_merges_source_tools(self):
        f1 = NormalizedFinding(
            id="http-missing-hsts",
            title="HSTS Missing",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            source_tool="Nuclei",
            port=443,
        )
        f2 = NormalizedFinding(
            id="http-missing-hsts",
            title="HSTS Missing",
            severity=Severity.LOW,
            confidence=Confidence.SUSPECTED,
            source_tool="Nikto",
            port=443,
        )
        merged = FindingCorrelator.deduplicate_findings([f1, f2])
        assert len(merged) == 1
        assert merged[0].source_tool == "Nuclei, Nikto"

    async def test_banner_probe_local_tcp_greeting_and_errors(self):
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            writer.write(b"SSH-2.0-OpenSSH_9.6p1 Debian\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            res = await BannerProbe.grab_tcp_banner("127.0.0.1", port, timeout=2.0)
            assert res is not None
            assert res.port == port
            assert res.service_name == "ssh"
            assert res.service_version == "SSH-2.0-OpenSSH_9.6p1 Debian"
            assert res.source_tool == "SocketBanner"
            assert res.source_tools == ["SocketBanner"]
        finally:
            server.close()
            await server.wait_closed()

        assert await BannerProbe.grab_tcp_banner("127.0.0.1", port, timeout=0.5) is None
        assert BannerProbe._inspect_tls_sync("127.0.0.1", port, None, 0.5) is None

    def test_reports_include_source_attribution_and_audit(self):
        report = FinalReport(
            metadata=ScanMetadata(
                scan_id="SCN-20261111-ATTR1",
                target="57.144.40.1",
                target_type="ipv4",
                profile="quick",
                start_time=datetime.now(timezone.utc),
                status="completed",
            ),
            target=TargetModel(
                raw_input="57.144.40.1",
                normalized_target="57.144.40.1",
                target_type="ipv4",
                resolved_ips=["57.144.40.1"],
            ),
            reconnaissance={
                "ip_intel": {
                    "rdap_name": "FB-BLOCK",
                    "country": "IE",
                    "source_tool": "IpIntelligence",
                }
            },
            ports=[
                PortResult(
                    port=443,
                    state=PortState.OPEN,
                    discovery_source="RustScan, Naabu",
                    source_tools=["RustScan", "Naabu"],
                )
            ],
            services=[
                ServiceResult(
                    port=443,
                    service_name="https",
                    service_version="TLSv1.3",
                    banner="Title: Error | TLSv1.3",
                    source_tool="httpx, TLSProbe",
                    source_tools=["httpx", "TLSProbe"],
                )
            ],
            findings=[
                NormalizedFinding(
                    id="deprecated-tls",
                    title="Deprecated TLS",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    source_tool="Nuclei",
                    port=443,
                )
            ],
            tool_summary={
                "RustScan": {"status": "completed", "ports_found": 1},
                "Nuclei": {"status": "completed", "findings": 1},
            },
            skipped_stages=["Nmap (not installed)"],
        )

        md = ReportGenerator.generate_markdown(report)
        assert "Found by: `IpIntelligence`" in md
        assert "| Source Tool(s) |" in md
        assert "httpx, TLSProbe" in md
        assert "**Source Tool:** `Nuclei`" in md

        html_out = HtmlReportExporter.export(report)
        assert "<th>Source Tool(s)</th>" in html_out
        assert "RustScan, Naabu" in html_out
        assert "httpx, TLSProbe" in html_out
        assert "Tool Execution Audit" in html_out
        assert "Skipped Stages" in html_out
        assert "Nmap (not installed)" in html_out

    def test_ai_summary_three_paragraph_normalization(self):
        messy = (
            "### 1. Summary\n"
            "**Paragraph 1 (What We Found):** Ports `80` and `443` are open [RustScan, Naabu] with HTTP/3 [httpx].\n\n"
            "- **What We Can Do Next:** Audit older TLS 1.0/1.1 settings [Nuclei].\n\n"
            "3. Start Right Now: Turn off older TLS 1.0 and TLS 1.1 on port 443 first."
        )
        cleaned = format_three_paragraph_summary(messy)
        paras = cleaned.split("\n\n")
        assert len(paras) == 3
        assert "**" not in cleaned
        assert "`" not in cleaned
        assert "###" not in cleaned
        assert paras[0].startswith("Ports 80 and 443")
        assert paras[1].startswith("Audit older TLS")
        assert paras[2].startswith("Turn off older TLS")

        model = build_ai_report_model("SCN-20261112-AI1", "test-model", messy)
        assert model.executive_summary == cleaned
        assert model.conclusion == paras[2]
        assert model.recommendations == f"{paras[1]}\n\n{paras[2]}"
