"""Integration tests validating parsers against synthetic tool output fixtures."""

import json
from pathlib import Path
import unittest

from app.parsers.nmap_parser import NmapParser
from app.parsers.nuclei_parser import NucleiParser
from app.reports.schemas import Severity
from app.scanners.nikto import NiktoAdapter
from app.scanners.whatweb import WhatWebAdapter


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestFixtures(unittest.TestCase):
    def test_nmap_fixture(self):
        xml_content = (FIXTURES_DIR / "sample_nmap.xml").read_text(encoding="utf-8")
        ports, services, findings = NmapParser.parse_xml(xml_content)

        self.assertEqual(len(ports), 4)
        port_nums = [p.port for p in ports]
        self.assertListEqual(port_nums, [22, 80, 443, 3306])

        # Verify service detection
        svc_names = [s.service_name for s in services]
        self.assertIn("ssh", svc_names)
        self.assertIn("http", svc_names)
        self.assertIn("https", svc_names)
        self.assertIn("mysql", svc_names)

        # Verify NSE script findings
        self.assertTrue(any("http-title" in f.title for f in findings))
        self.assertTrue(any("ssl-cert" in f.title for f in findings))

    def test_nuclei_fixture(self):
        jsonl_content = (FIXTURES_DIR / "sample_nuclei.jsonl").read_text(encoding="utf-8")
        findings = NucleiParser.parse_jsonl(jsonl_content)

        self.assertEqual(len(findings), 3)

        # Log4Shell
        log4j = next(f for f in findings if f.id == "cve-2021-44228")
        self.assertEqual(log4j.severity, Severity.CRITICAL)
        self.assertEqual(log4j.cve_id, "CVE-2021-44228")
        self.assertIn("Upgrade to Log4j", log4j.remediation)

        # Git config
        git_f = next(f for f in findings if f.id == "git-config")
        self.assertEqual(git_f.severity, Severity.MEDIUM)
        self.assertIn("core", git_f.evidence)

    def test_whatweb_fixture(self):
        json_content = (FIXTURES_DIR / "sample_whatweb.json").read_text(encoding="utf-8")
        adapter = WhatWebAdapter()
        services = adapter.parse_services(json_content)

        self.assertEqual(len(services), 1)
        svc = services[0]
        self.assertEqual(svc.port, 443)
        self.assertIn("HTTPServer 1.18.0", svc.service_version)
        self.assertTrue(any("Bootstrap 5.1.3" in t for t in svc.technologies))

    def test_nikto_fixture(self):
        json_content = (FIXTURES_DIR / "sample_nikto.json").read_text(encoding="utf-8")
        adapter = NiktoAdapter()
        import asyncio
        findings = asyncio.run(adapter.parse_output(json_content))

        self.assertEqual(len(findings), 3)
        # Verify RCE was elevated to HIGH severity
        rce_f = next(f for f in findings if "Apache 2.4.49" in f.title)
        self.assertEqual(rce_f.severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
