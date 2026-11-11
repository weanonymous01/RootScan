"""Lightweight non-destructive TCP banner and TLS certificate inspector."""

from __future__ import annotations

import asyncio
import socket
import ssl
from typing import List, Optional

from app.reports.schemas import ServiceResult


NON_HTTP_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6379}
TLS_PORTS = {443, 465, 636, 993, 995, 8443}


class BannerProbe:
    """Non-destructive TCP greeting banner grabber and TLS handshake inspector."""

    BANNER_TOOL = "SocketBanner"
    TLS_TOOL = "TLSProbe"

    @staticmethod
    async def grab_tcp_banner(target: str, port: int, timeout: float = 4.0) -> Optional[ServiceResult]:
        """Read initial greeting banner (e.g., SSH, FTP, SMTP) over TCP without sending payloads."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
            try:
                raw = await asyncio.wait_for(reader.read(512), timeout=timeout)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            banner_text = raw.decode("utf-8", errors="replace").strip()
            # Keep only printable first line
            first_line = "".join(ch for ch in banner_text.splitlines()[0] if ch.isprintable()).strip() if banner_text else ""
            if not first_line:
                return None

            svc_name = None
            svc_version = None
            if first_line.upper().startswith("SSH-"):
                svc_name = "ssh"
                svc_version = first_line
            elif first_line.startswith("220") and "FTP" in first_line.upper():
                svc_name = "ftp"
                svc_version = first_line
            elif first_line.startswith("220"):
                svc_name = "smtp"
                svc_version = first_line

            return ServiceResult(
                port=port,
                protocol="tcp",
                state="open",
                service_name=svc_name,
                service_version=svc_version,
                banner=f"Banner: {first_line[:90]}",
                source_tool=BannerProbe.BANNER_TOOL,
                source_tools=[BannerProbe.BANNER_TOOL]
            )
        except Exception:
            return None

    @staticmethod
    def _inspect_tls_sync(target: str, port: int, sni_host: Optional[str], timeout: float) -> Optional[ServiceResult]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni_host or target) as ssock:
                    tls_ver = ssock.version() or "TLS"
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else ""
                    parts = [tls_ver]
                    if cipher_name:
                        parts.append(cipher_name)

                    # Read binary cert DER if available
                    der_cert = ssock.getpeercert(binary_form=True)
                    techs = [tls_ver]
                    if der_cert:
                        parts.append(f"Cert({len(der_cert)}B DER)")

                    return ServiceResult(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service_name="https" if port in (443, 8443) else None,
                        banner=" | ".join(parts),
                        technologies=techs,
                        source_tool=BannerProbe.TLS_TOOL,
                        source_tools=[BannerProbe.TLS_TOOL]
                    )
        except Exception:
            return None

    @staticmethod
    async def inspect_tls(target: str, port: int, sni_host: Optional[str] = None, timeout: float = 4.0) -> Optional[ServiceResult]:
        """Inspect negotiated TLS protocol, cipher suite, and certificate metadata."""
        return await asyncio.to_thread(BannerProbe._inspect_tls_sync, target, port, sni_host, timeout)

    @classmethod
    async def probe_services(cls, target: str, ports: List[int], sni_host: Optional[str] = None) -> List[ServiceResult]:
        """Run concurrent TCP banner grabbing and TLS inspection across eligible ports."""
        tasks = []
        for p in ports:
            if p in NON_HTTP_BANNER_PORTS:
                tasks.append(cls.grab_tcp_banner(target, p))
            elif p in TLS_PORTS:
                tasks.append(cls.inspect_tls(target, p, sni_host=sni_host))

        if not tasks:
            return []

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in raw_results if isinstance(r, ServiceResult)]

