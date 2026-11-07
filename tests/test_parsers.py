"""Unit tests for tool output parsers (Nmap XML, Nuclei JSONL)."""

import unittest
from app.parsers.nmap_parser import NmapParser
from app.parsers.nuclei_parser import NucleiParser
from app.reports.schemas import Severity


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
<host>
  <status state="up"/>
  <address addr="45.33.32.156" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache httpd" version="2.4.41"/>
      <script id="http-title" output="Go ahead and ScanMe!"/>
    </port>
  </ports>
</host>
</nmaprun>
"""

SAMPLE_NUCLEI_JSONL = """
{"template-id":"cve-2021-41773","info":{"name":"Apache 2.4.49/2.4.50 Path Traversal","severity":"critical","description":"Apache Path Traversal and RCE","classification":{"cve-id":"CVE-2021-41773"},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]},"matched-at":"http://target.local:80/icons/.%%32%65/etc/passwd"}
{"template-id":"ssl-issuer","info":{"name":"SSL Certificate Issuer","severity":"info","description":"Extract SSL certificate details"},"matched-at":"https://target.local:443"}
"""


class TestParsers(unittest.TestCase):
    def test_nmap_parser_valid_xml(self):
        ports, services, findings = NmapParser.parse_xml(SAMPLE_NMAP_XML)
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0].port, 22)
        self.assertEqual(ports[1].port, 80)
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0].service_name, "ssh")
        self.assertIn("OpenSSH", services[0].service_version)
        self.assertEqual(services[1].service_name, "http")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Nmap NSE: http-title")

    def test_nmap_parser_malformed_xml(self):
        ports, services, findings = NmapParser.parse_xml("<broken xml>>>")
        self.assertEqual(ports, [])
        self.assertEqual(services, [])
        self.assertEqual(findings, [])

    def test_nuclei_parser_valid_jsonl(self):
        findings = NucleiParser.parse_jsonl(SAMPLE_NUCLEI_JSONL)
        self.assertEqual(len(findings), 2)
        critical_f = findings[0]
        self.assertEqual(critical_f.id, "cve-2021-41773")
        self.assertEqual(critical_f.severity, Severity.CRITICAL)
        self.assertEqual(critical_f.cve_id, "CVE-2021-41773")
        self.assertIn("target.local", critical_f.evidence)

        info_f = findings[1]
        self.assertEqual(info_f.severity, Severity.INFO)

    def test_nuclei_parser_malformed_jsonl(self):
        findings = NucleiParser.parse_jsonl("not json at all\n{bad json}")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

