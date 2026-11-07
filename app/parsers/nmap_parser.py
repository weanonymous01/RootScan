"""Nmap XML and text output parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List, Tuple

from app.reports.schemas import Confidence, NormalizedFinding, PortResult, PortState, ServiceResult, Severity


class NmapParser:
    """Parses Nmap XML output into normalized ports, services, and findings."""

    @staticmethod
    def parse_xml(xml_content: str) -> Tuple[List[PortResult], List[ServiceResult], List[NormalizedFinding]]:
        ports: List[PortResult] = []
        services: List[ServiceResult] = []
        findings: List[NormalizedFinding] = []

        if not xml_content or not xml_content.strip():
            return ports, services, findings

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return ports, services, findings

        for host in root.findall("host"):
            # Ports
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                port_id = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "open") if state_elem is not None else "open"
                
                if state == "open":
                    port_res = PortResult(
                        port=port_id,
                        protocol=protocol,
                        state=PortState.OPEN,
                        discovery_source="Nmap"
                    )
                    ports.append(port_res)

                    # Service detection
                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else None
                    product = service_elem.get("product") if service_elem is not None else None
                    version = service_elem.get("version") if service_elem is not None else None
                    extrainfo = service_elem.get("extrainfo") if service_elem is not None else None

                    full_version = " ".join(filter(None, [product, version, extrainfo])) or None
                    banner = f"{service_name or ''} {full_version or ''}".strip() or None

                    service_res = ServiceResult(
                        port=port_id,
                        protocol=protocol,
                        state=state,
                        service_name=service_name,
                        service_version=full_version,
                        banner=banner,
                        source_tool="Nmap"
                    )
                    services.append(service_res)

                    # Scripts / Vulnerabilities
                    for script in port_elem.findall("script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")
                        
                        # Check for vulnerability indicators in NSE script
                        severity = Severity.INFO
                        if "vuln" in script_id.lower() or "VULNERABLE" in script_output:
                            severity = Severity.HIGH

                        findings.append(NormalizedFinding(
                            title=f"Nmap NSE: {script_id}",
                            severity=severity,
                            confidence=Confidence.CONFIRMED if severity != Severity.INFO else Confidence.SUSPECTED,
                            source_tool="Nmap",
                            port=port_id,
                            protocol=protocol,
                            evidence=script_output.strip(),
                            affected_component=service_name,
                            observed_version=full_version
                        ))

        return ports, services, findings

