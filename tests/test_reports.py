"""Unit tests for report generation and storage."""

from datetime import datetime
from pathlib import Path
import re
import tempfile
import unittest

from app.reports.generator import ReportGenerator
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


class TestReports(unittest.TestCase):
    def test_scan_id_format(self):
        scan_id = generate_scan_id()
        pattern = r"^SCN-\d{8}-[A-F0-9]{5}$"
        self.assertRegex(scan_id, pattern)

    def test_scan_id_uniqueness(self):
        ids = {generate_scan_id() for _ in range(100)}
        self.assertEqual(len(ids), 100)

    def test_markdown_report_generation(self):
        meta = ScanMetadata(
            scan_id="SCN-20261107-TEST1",
            target="target.local",
            target_type="domain",
            profile="standard",
            start_time=datetime.utcnow(),
            status="completed"
        )
        target = TargetModel(
            raw_input="target.local",
            normalized_target="target.local",
            target_type="domain",
            resolved_ips=["1.2.3.4"]
        )
        port = PortResult(port=80, protocol="tcp", state=PortState.OPEN, discovery_source="Nmap")
        service = ServiceResult(port=80, protocol="tcp", service_name="http", service_version="Apache 2.4")
        finding = NormalizedFinding(
            title="Apache Traversal",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            cve_id="CVE-2021-41773",
            source_tool="Nuclei",
            evidence="Observed path traversal vulnerability."
        )

        report = FinalReport(
            metadata=meta,
            target=target,
            ports=[port],
            services=[service],
            findings=[finding]
        )

        md = ReportGenerator.generate_markdown(report)
        self.assertIn("RootScan Security Assessment Report", md)
        self.assertIn("SCN-20261107-TEST1", md)
        self.assertIn("CVE-2021-41773", md)
        self.assertIn("Apache 2.4", md)
        self.assertIn("[HIGH]", md)


if __name__ == "__main__":
    unittest.main()

