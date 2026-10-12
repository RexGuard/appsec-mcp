"""SSRF guard for the website check: only public http(s) targets unless explicitly allowed."""

import ipaddress
import logging
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from appsec_mcp.errors import ErrorCode, WebCheckError

logger = logging.getLogger(__name__)

Resolver = Callable[[str, int], list[str]]
_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_URL_LENGTH = 2048


@dataclass(frozen=True)
class Target:
    """A validated URL target."""

    url: str
    scheme: str
    host: str
    port: int


def system_resolver(host: str, port: int) -> list[str]:
    """Resolve a host to IP strings with the system resolver."""
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


def parse_target(url: str) -> Target:
    """Validate the URL shape. Raises URL_INVALID."""
    if len(url) > _MAX_URL_LENGTH:
        raise WebCheckError(ErrorCode.URL_INVALID, "That URL is too long.")
    parts = urlsplit(url.strip())
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise WebCheckError(
            ErrorCode.URL_INVALID,
            "Give a full http:// or https:// address, like https://myapp.com.",
        )
    if parts.username or parts.password:
        raise WebCheckError(ErrorCode.URL_INVALID, "URLs with a username or password are refused.")
    try:
        port = parts.port or _DEFAULT_PORTS[parts.scheme]
    except ValueError as exc:
        raise WebCheckError(ErrorCode.URL_INVALID, "The port in that URL is not valid.") from exc
    return Target(url=url.strip(), scheme=parts.scheme, host=parts.hostname, port=port)


def is_blocked_ip(raw: str) -> bool:
    """True for private, loopback, link-local, reserved, multicast or unspecified addresses."""
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def check_target(target: Target, allow_private: bool, resolver: Resolver) -> list[str]:
    """Resolve the host and refuse internal addresses. Returns the resolved IPs."""
    try:
        addresses = resolver(target.host, target.port)
    except OSError as exc:
        logger.info("DNS lookup failed for %s: %s", target.host, exc)
        raise WebCheckError(ErrorCode.URL_INVALID, f"'{target.host}' could not be found.") from exc
    if not addresses:
        raise WebCheckError(ErrorCode.URL_INVALID, f"'{target.host}' has no address.")
    if not allow_private and any(is_blocked_ip(a) for a in addresses):
        raise WebCheckError(
            ErrorCode.URL_PRIVATE_BLOCKED,
            f"'{target.host}' points to a private or local address, so it was not checked. "
            "Pass allow_private=true only for your own local or internal site.",
        )
    return addresses
