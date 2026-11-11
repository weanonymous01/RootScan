"""IP intelligence, reverse DNS, and RDAP network metadata."""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, Optional
import httpx


def _extract_rdap_org(data: Dict[str, Any]) -> Optional[str]:
    """Extract primary organization or entity name from RDAP JSON entities."""
    for entity in data.get("entities", []) or []:
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                    return str(prop[3]).strip()
        if entity.get("handle"):
            return str(entity["handle"])
    return None


class IpIntelligence:
    """Collects network ownership, ASN/RDAP netblock, and reverse DNS records."""

    TOOL_NAME = "IpIntelligence"

    @staticmethod
    async def gather(ip_address: str) -> Dict[str, Any]:
        """Perform reverse DNS and global RDAP lookup for an IP."""
        results: Dict[str, Any] = {
            "source_tool": IpIntelligence.TOOL_NAME,
            "ip_address": ip_address,
            "reverse_dns": None,
            "rdap": {}
        }

        # Reverse DNS lookup (executed in thread to avoid blocking event loop)
        try:
            hostname, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip_address)
            results["reverse_dns"] = hostname
        except Exception:
            results["reverse_dns"] = None

        # Global RDAP lookup (follows RIR bootstrap redirects: ARIN, RIPE, APNIC, etc.)
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=8.0) as client:
                resp = await client.get(
                    f"https://rdap.org/ip/{ip_address}",
                    headers={"Accept": "application/rdap+json, application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    cidrs = []
                    for c in data.get("cidr0_cidrs", []) or []:
                        prefix = c.get("v4prefix") or c.get("v6prefix")
                        length = c.get("length")
                        if prefix and length is not None:
                            cidrs.append(f"{prefix}/{length}")

                    results["rdap"] = {
                        "name": data.get("name"),
                        "handle": data.get("handle"),
                        "org": _extract_rdap_org(data),
                        "cidr": ", ".join(cidrs) if cidrs else None,
                        "start_address": data.get("startAddress"),
                        "end_address": data.get("endAddress"),
                        "country": data.get("country"),
                    }
        except Exception:
            pass

        return results
