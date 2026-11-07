"""DNS and domain reconnaissance intelligence."""

from __future__ import annotations

import socket
from typing import Any, Dict, List
import dns.resolver


class DnsIntelligence:
    """Collects DNS record intelligence for a domain target."""

    @staticmethod
    async def gather(domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS record resolution."""
        results: Dict[str, Any] = {
            "domain": domain,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
        }

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        for r_type, key in [
            ("A", "a_records"),
            ("AAAA", "aaaa_records"),
            ("MX", "mx_records"),
            ("NS", "ns_records"),
            ("TXT", "txt_records"),
        ]:
            try:
                answers = resolver.resolve(domain, r_type)
                for rdata in answers:
                    results[key].append(str(rdata))
            except Exception:
                continue

        return results

