"""Target validation, normalization, and security scope checks for RootScan."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
import socket
from typing import List, Optional
from urllib.parse import urlparse


class TargetType(str, Enum):
    IP_V4 = "ipv4"
    IP_V6 = "ipv6"
    DOMAIN = "domain"
    INVALID = "invalid"


@dataclass
class ValidationResult:
    is_valid: bool
    target_type: TargetType
    original_input: str
    normalized_target: str
    resolved_ips: List[str] = field(default_factory=list)
    is_private: bool = False
    is_loopback: bool = False
    is_cloud_metadata: bool = False
    is_reserved: bool = False
    error_message: Optional[str] = None
    warning_message: Optional[str] = None


# Cloud metadata IP addresses (AWS, GCP, Azure, DigitalOcean, etc.)
METADATA_IPS = {
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    ipaddress.ip_network("100.100.100.200/32"), # Alibaba
}

# Blocked special ranges
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 loopback
    ipaddress.ip_network("169.254.0.0/16"),    # IPv4 link-local / metadata
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

# RFC 1918 & IPv6 Unique Local
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]

# Hostname regex (RFC 1123)
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def normalize_target_input(raw_input: str) -> str:
    """Normalize user input by trimming whitespace and stripping URI schemes/paths if present."""
    target = raw_input.strip()
    
    # If user passed a full URL (e.g. https://example.com/api), extract the hostname
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or target
    elif "/" in target and not re.search(r"/\d+$", target):
        # Path without scheme (e.g. example.com/test)
        target = target.split("/")[0]

    # Strip port if present in domain format (e.g. example.com:8080)
    if ":" in target and not target.startswith("[") and target.count(":") == 1:
        host, _, _ = target.partition(":")
        # Check if the host part is not an IPv6
        if not host.replace(".", "").isdigit():
            target = host

    return target.strip().rstrip(".").lower()


def validate_ip_address(ip_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Attempt to parse string as an IPv4 or IPv6 address."""
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def is_ip_in_networks(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    """Check if an IP belongs to any of the specified networks."""
    for net in networks:
        try:
            if ip in net:
                return True
        except TypeError:
            continue
    return False


def validate_target(raw_target: str, allow_private: bool = False) -> ValidationResult:
    """
    Validate target input against security policies and classify it.
    
    Args:
        raw_target: Raw string provided by user.
        allow_private: Whether private IP scanning has been explicitly authorized.
    """
    if not raw_target or not raw_target.strip():
        return ValidationResult(
            is_valid=False,
            target_type=TargetType.INVALID,
            original_input=raw_target,
            normalized_target="",
            error_message="Target cannot be empty."
        )

    normalized = normalize_target_input(raw_target)

    # 1. Check if input is a direct IP address
    parsed_ip = validate_ip_address(normalized)
    if parsed_ip:
        target_type = TargetType.IP_V4 if isinstance(parsed_ip, ipaddress.IPv4Address) else TargetType.IP_V6
        is_loopback = parsed_ip.is_loopback
        is_reserved = parsed_ip.is_reserved or parsed_ip.is_multicast
        is_metadata = is_ip_in_networks(parsed_ip, list(METADATA_IPS))
        is_private = parsed_ip.is_private

        # Security check: Block metadata and loopback destinations
        if is_metadata:
            return ValidationResult(
                is_valid=False,
                target_type=target_type,
                original_input=raw_target,
                normalized_target=str(parsed_ip),
                is_cloud_metadata=True,
                error_message="Scanning cloud metadata services (169.254.169.254) is prohibited."
            )

        if is_loopback:
            return ValidationResult(
                is_valid=False,
                target_type=target_type,
                original_input=raw_target,
                normalized_target=str(parsed_ip),
                is_loopback=True,
                error_message="Loopback scanning (127.0.0.1 / ::1) is blocked by default."
            )

        # Check blocked networks
        if is_ip_in_networks(parsed_ip, BLOCKED_NETWORKS):
            return ValidationResult(
                is_valid=False,
                target_type=target_type,
                original_input=raw_target,
                normalized_target=str(parsed_ip),
                is_reserved=True,
                error_message=f"IP address {parsed_ip} falls into a restricted/reserved network range."
            )

        # Check private network scope authorization
        warning_message = None
        if is_private and not allow_private:
            return ValidationResult(
                is_valid=False,
                target_type=target_type,
                original_input=raw_target,
                normalized_target=str(parsed_ip),
                is_private=True,
                error_message="Target is a private IP. Explicit internal authorization scope confirmation is required."
            )
        elif is_private and allow_private:
            warning_message = "Target is a private IP. Internal assessment scope confirmed."

        return ValidationResult(
            is_valid=True,
            target_type=target_type,
            original_input=raw_target,
            normalized_target=str(parsed_ip),
            resolved_ips=[str(parsed_ip)],
            is_private=is_private,
            is_loopback=is_loopback,
            is_cloud_metadata=is_metadata,
            is_reserved=is_reserved,
            warning_message=warning_message
        )

    # 2. Check if input is a valid domain/hostname
    if DOMAIN_REGEX.match(normalized):
        # Try DNS resolution to verify domain and inspect resolved IPs
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(normalized, None)
            for item in addr_info:
                ip_addr = item[4][0]
                if ip_addr not in resolved_ips:
                    resolved_ips.append(ip_addr)
        except (socket.gaierror, socket.herror) as e:
            return ValidationResult(
                is_valid=False,
                target_type=TargetType.DOMAIN,
                original_input=raw_target,
                normalized_target=normalized,
                error_message=f"Domain '{normalized}' could not be resolved: {e}"
            )

        if not resolved_ips:
            return ValidationResult(
                is_valid=False,
                target_type=TargetType.DOMAIN,
                original_input=raw_target,
                normalized_target=normalized,
                error_message=f"No DNS records (A/AAAA) found for '{normalized}'."
            )

        # Check resolved addresses against blocked/metadata ranges (Anti-SSRF / DNS rebinding defense)
        has_private_res = False
        for ip_str in resolved_ips:
            pip = validate_ip_address(ip_str)
            if pip:
                if is_ip_in_networks(pip, list(METADATA_IPS)):
                    return ValidationResult(
                        is_valid=False,
                        target_type=TargetType.DOMAIN,
                        original_input=raw_target,
                        normalized_target=normalized,
                        resolved_ips=resolved_ips,
                        is_cloud_metadata=True,
                        error_message="Domain resolves to cloud metadata endpoint (Anti-SSRF triggered)."
                    )
                if pip.is_loopback or is_ip_in_networks(pip, BLOCKED_NETWORKS):
                    return ValidationResult(
                        is_valid=False,
                        target_type=TargetType.DOMAIN,
                        original_input=raw_target,
                        normalized_target=normalized,
                        resolved_ips=resolved_ips,
                        is_loopback=True,
                        error_message=f"Domain resolves to loopback or restricted IP ({pip}). Assessment rejected."
                    )
                if pip.is_private:
                    has_private_res = True

        if has_private_res and not allow_private:
            return ValidationResult(
                is_valid=False,
                target_type=TargetType.DOMAIN,
                original_input=raw_target,
                normalized_target=normalized,
                resolved_ips=resolved_ips,
                is_private=True,
                error_message="Domain resolves to internal/private IP. Explicit authorization confirmation required."
            )

        return ValidationResult(
            is_valid=True,
            target_type=TargetType.DOMAIN,
            original_input=raw_target,
            normalized_target=normalized,
            resolved_ips=resolved_ips,
            is_private=has_private_res
        )

    # 3. Neither valid IP nor valid domain
    return ValidationResult(
        is_valid=False,
        target_type=TargetType.INVALID,
        original_input=raw_target,
        normalized_target=normalized,
        error_message=f"Invalid target format: '{raw_target}'. Expected valid IPv4, IPv6, or domain name."
    )

