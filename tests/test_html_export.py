"""Unit tests for standalone HTML report generation (FR-19)."""

from datetime import datetime
import unittest

from app.reports.html_exporter import HtmlReportExporter
from app.reports.schemas import (
    FinalReport,
    NormalizedFinding,
    PortResult,
    PortState,
    ScanMetadata,
    ServiceResult,
    Severity,
    TargetModel,
)


class TestHtmlExport(unittest.TestCase):
    def test_html_export_structure(self):
        meta = ScanMetadata(
            scan_id="SCN-20261107-HTML1",
            target="test.local",
            target_type="domain",
            profile="standard",
            start_time=datetime.utcnow()
        )
        target = TargetModel(raw_input="test.local", normalized_target="test.local", target_type="domain")
        report = FinalReport(
            metadata=meta,
            target=target,
            ports=[PortResult(port=443, discovery_source="Nmap")],
            services=[ServiceResult(port=443, service_name="https", banner="nginx 1.20")],
            findings=[NormalizedFinding(
                title="Strict-Transport-Security Missing",
                severity=Severity.LOW,
                source_tool="Nuclei",
                remediation="Enable HSTS response header."
            )]
        )

        html_out = HtmlReportExporter.export(report)
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("SCN-20261107-HTML1", html_out)
        self.assertIn("Strict-Transport-Security Missing", html_out)
        self.assertIn("Enable HSTS response header", html_out)
        self.assertIn("badge-low", html_out)


if __name__ == "__main__":
    unittest.main()
