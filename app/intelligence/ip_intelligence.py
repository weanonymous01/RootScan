"""IP intelligence, reverse DNS, and RDAP network metadata."""

from __future__ import annotations

import socket
from typing import Any, Dict
import httpx


class IpIntelligence:
    """Collects network ownership, ASN, and reverse DNS records."""

    @staticmethod
    async def gather(ip_address: str) -> Dict[str, Any]:
        """Perform reverse DNS and RDAP lookup for an IP."""
        results: Dict[str, Any] = {
            "ip_address": ip_address,
            "reverse_dns": None,
            "rdap": {}
        }

        # Reverse DNS lookup
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            results["reverse_dns"] = hostname
        except Exception:
            results["reverse_dns"] = None

        # RDAP Lookup (Public ARIN bootstrap)
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(f"https://rdap.arin.net/registry/ip/{ip_address}", headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    data = resp.json()
                    results["rdap"] = {
                        "name": data.get("name"),
                        "handle": data.get("handle"),
                        "start_address": data.get("startAddress"),
                        "end_address": data.get("endAddress"),
                        "country": data.get("country"),
                    }
        except Exception:
            pass

        return results

