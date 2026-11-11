"""DNS and domain reconnaissance intelligence."""

from __future__ import annotations

from typing import Any, Dict, List
import dns.resolver


class DnsIntelligence:
    """Collects DNS record intelligence for a domain target."""

    TOOL_NAME = "DnsIntelligence"

    @staticmethod
    async def gather(domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS record resolution."""
        results: Dict[str, Any] = {
            "source_tool": DnsIntelligence.TOOL_NAME,
            "domain": domain,
            "a_records": [],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
            "ns_records": [],
            "soa_records": [],
            "txt_records": [],
        }

        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 4.0

        record_types = [
            ("A", "a_records"),
            ("AAAA", "aaaa_records"),
            ("CNAME", "cname_records"),
            ("MX", "mx_records"),
            ("NS", "ns_records"),
            ("SOA", "soa_records"),
            ("TXT", "txt_records"),
        ]

        for r_type, key in record_types:
            try:
                answers = resolver.resolve(domain, r_type)
                for rdata in answers:
                    results[key].append(str(rdata))
            except Exception:
                continue

        return results
