"""Unit tests for finding deduplication, service linking, and correlation."""

import unittest
from app.intelligence.correlation import FindingCorrelator
from app.reports.schemas import Confidence, NormalizedFinding, ServiceResult, Severity


class TestCorrelation(unittest.TestCase):
    def test_deduplicate_identical_findings(self):
        f1 = NormalizedFinding(
            title="TLS Weak Cipher",
            severity=Severity.MEDIUM,
            confidence=Confidence.SUSPECTED,
            source_tool="Nuclei",
            port=443,
            references=["https://example.com/ref1"]
        )
        f2 = NormalizedFinding(
            title="TLS Weak Cipher",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            source_tool="Nmap",
            port=443,
            references=["https://example.com/ref2"]
        )
        merged = FindingCorrelator.deduplicate_findings([f1, f2])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].confidence, Confidence.CONFIRMED)
        self.assertIn("https://example.com/ref1", merged[0].references)
        self.assertIn("https://example.com/ref2", merged[0].references)

    def test_link_findings_to_services(self):
        service = ServiceResult(port=80, protocol="tcp", service_name="Apache httpd", service_version="2.4.49")
        finding = NormalizedFinding(
            title="Path Traversal",
            severity=Severity.CRITICAL,
            source_tool="Nuclei",
            port=80
        )
        linked = FindingCorrelator.link_findings_to_services([service], [finding])
        self.assertEqual(linked[0].affected_component, "Apache httpd")
        self.assertEqual(linked[0].observed_version, "2.4.49")


if __name__ == "__main__":
    unittest.main()
