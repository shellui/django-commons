"""RFC 8707 resource indicators for MCP (audience = canonical ``/mcp`` URL)."""

from __future__ import annotations

import hmac
import ipaddress
from urllib.parse import urlsplit

MCP_RESOURCE_SUFFIX = '/mcp'
_LOOPBACK_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1'})
# RFC 6598 shared space (Tailscale etc.). Not ``is_private`` on modern Python.
_CGNAT_SHARED = ipaddress.ip_network('100.64.0.0/10')


def mcp_resource_from_origin(origin: str) -> str:
    """Build the protected resource identifier for a Shellui service origin."""
    base = str(origin or '').strip().rstrip('/')
    if not base:
        return ''
    return f'{base}{MCP_RESOURCE_SUFFIX}'


def _http_dev_host_allowed(host: str | None) -> bool:
    """Loopback names/IPs and private/CGNAT IP literals (LAN / Tailscale)."""
    h = (host or '').lower()
    if h in _LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local or ip in _CGNAT_SHARED)


def normalize_resource_indicator(raw: str | None) -> str | None:
    """
    Canonical resource URL for authorize/token/refresh ``resource`` parameter.
    Must be absolute https (or http on loopback/private IP) ending in ``/mcp`` with no fragment.
    """
    s = str(raw or '').strip()
    if not s or '#' in s:
        return None
    if s.endswith('/'):
        s = s.rstrip('/')
    if not s.endswith(MCP_RESOURCE_SUFFIX):
        return None
    try:
        parsed = urlsplit(s)
    except ValueError:
        return None
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return None
    if parsed.path != MCP_RESOURCE_SUFFIX:
        return None
    if parsed.query or parsed.fragment:
        return None
    if parsed.scheme == 'http' and not _http_dev_host_allowed(parsed.hostname):
        return None
    return s


def access_token_audience_matches(payload: dict, expected_resource: str) -> bool:
    """True when JWT ``aud`` equals this service's MCP resource URL."""
    expected = normalize_resource_indicator(expected_resource) or ''
    presented = normalize_resource_indicator(str(payload.get('aud') or '')) or ''
    if not expected or not presented:
        return False
    return hmac.compare_digest(expected, presented)
