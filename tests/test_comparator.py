"""Unit tests for assessment comparison diffing (FR-18)."""

from datetime import datetime
import unittest

from app.reports.comparator import ReportComparator
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


class TestComparator(unittest.TestCase):
    def test_compare_scans(self):
        meta_old = ScanMetadata(scan_id="SCN-OLD", target="site.local", target_type="domain", profile="quick", start_time=datetime.utcnow())
        meta_new = ScanMetadata(scan_id="SCN-NEW", target="site.local", target_type="domain", profile="quick", start_time=datetime.utcnow())
        target = TargetModel(raw_input="site.local", normalized_target="site.local", target_type="domain")

        report_old = FinalReport(
            metadata=meta_old,
            target=target,
            ports=[PortResult(port=80, discovery_source="Nmap")],
            services=[ServiceResult(port=80, service_name="http", service_version="1.0")],
            findings=[NormalizedFinding(title="Old Vuln", severity=Severity.LOW, source_tool="Nuclei")]
        )

        report_new = FinalReport(
            metadata=meta_new,
            target=target,
            ports=[
                PortResult(port=80, discovery_source="Nmap"),
                PortResult(port=443, discovery_source="Nmap")
            ],
            services=[
                ServiceResult(port=80, service_name="http", service_version="2.0"),
                ServiceResult(port=443, service_name="https", service_version="1.0")
            ],
            findings=[
                NormalizedFinding(title="New Vuln", severity=Severity.HIGH, source_tool="Nuclei")
            ]
        )

        diff = ReportComparator.compare(report_old, report_new)
        self.assertEqual(diff.new_open_ports, [443])
        self.assertEqual(diff.closed_ports, [])
        self.assertEqual(len(diff.new_findings), 1)
        self.assertEqual(diff.new_findings[0].title, "New Vuln")
        self.assertEqual(len(diff.resolved_findings), 1)
        self.assertEqual(diff.resolved_findings[0].title, "Old Vuln")
        self.assertEqual(len(diff.service_version_changes), 1)
        self.assertEqual(diff.service_version_changes[0]["old_version"], "1.0")
        self.assertEqual(diff.service_version_changes[0]["new_version"], "2.0")


if __name__ == "__main__":
    unittest.main()
