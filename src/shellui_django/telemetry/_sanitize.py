"""Redact span attributes that must not leave the process. No OpenTelemetry imports."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SQL_ATTRIBUTES = frozenset({'db.statement', 'db.query.text'})
_QUERY_ATTRIBUTES = frozenset({'url.query'})
_URL_ATTRIBUTES = frozenset({'url.full', 'http.url', 'http.target'})

_DOLLAR_TAG = re.compile(r'\$([A-Za-z_][A-Za-z0-9_]*)\$(.*?)\$\1\$', re.DOTALL)
_DOLLAR_BARE = re.compile(r'\$\$(.*?)\$\$', re.DOTALL)
_SINGLE_QUOTE = re.compile(r"'(?:''|[^'])*'")
_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)
_LINE_COMMENT = re.compile(r'--[^\n]*')
_NUMERIC_LITERAL = re.compile(r'(?<![$%:\w])(?:\d+\.\d+|\d+)(?!\w)')

_SENSITIVE_QUERY_NAMES = frozenset(
    {
        'token',
        'code',
        'key',
        'sig',
        'auth',
        'jwt',
        'password',
        'passwd',
        'secret',
        'session',
    }
)
_SENSITIVE_QUERY_FRAGMENTS = (
    'token',
    'password',
    'passwd',
    'secret',
    'api_key',
    'apikey',
    'signature',
    'credential',
    'session',
    'jwt',
)
_HEADER_MARKERS = (
    'authorization',
    'cookie',
    'token',
    'secret',
    'password',
    'session',
    'api_key',
    'apikey',
    'credential',
)
_DROPPED_ATTRIBUTES = frozenset(
    {
        'http.request.body',
        'http.response.body',
        'db.statement.parameters',
    }
)


def redact_sql(statement: str) -> str:
    """Replace SQL literals and comments with placeholders. Bind parameters stay."""
    redacted = _DOLLAR_TAG.sub('?', statement)
    redacted = _DOLLAR_BARE.sub('?', redacted)
    redacted = _SINGLE_QUOTE.sub('?', redacted)
    redacted = _BLOCK_COMMENT.sub(' ', redacted)
    redacted = _LINE_COMMENT.sub(' ', redacted)
    return _NUMERIC_LITERAL.sub('?', redacted)


def query_key_sensitive(key: str) -> bool:
    normalized = key.strip().lower().replace('-', '_')
    if normalized in _SENSITIVE_QUERY_NAMES:
        return True
    return any(fragment in normalized for fragment in _SENSITIVE_QUERY_FRAGMENTS)


def redact_query(query: str) -> str:
    if not query:
        return query
    pairs = parse_qsl(query, keep_blank_values=True)
    redacted = [(key, 'REDACTED' if query_key_sensitive(key) else value) for key, value in pairs]
    return urlencode(redacted)


def redact_url(url: str) -> str:
    """Drop userinfo and redact sensitive query values. The path is kept."""
    parts = urlsplit(url)
    netloc = parts.netloc
    if parts.username is not None or parts.password is not None:
        host = parts.hostname or ''
        if parts.port is not None:
            host = f'{host}:{parts.port}'
        netloc = f'REDACTED:REDACTED@{host}'
    query = redact_query(parts.query) if parts.query else parts.query
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _drop_attribute(name: str) -> bool:
    lowered = name.lower()
    if lowered in _DROPPED_ATTRIBUTES or lowered.startswith('db.query.parameter'):
        return True
    if '.header.' not in lowered and not lowered.startswith('header.'):
        return False
    header = lowered.rsplit('.', 1)[-1].replace('-', '_')
    return any(marker in header for marker in _HEADER_MARKERS)


def _sanitize_text(name: str, value: str) -> str:
    if name in _SQL_ATTRIBUTES:
        return redact_sql(value)
    if name in _QUERY_ATTRIBUTES:
        return redact_query(value)
    if name in _URL_ATTRIBUTES:
        return redact_url(value)
    return value


def _sanitize_value(name: str, value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_text(name, value)
    if isinstance(value, (bytes, bytearray)):
        return _sanitize_text(name, value.decode('utf-8', errors='replace'))
    if isinstance(value, (list, tuple)):
        sanitized = [_sanitize_value(name, item) for item in value]
        return type(value)(sanitized)
    return value


def sanitize_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of span attributes safe to export."""
    sanitized: dict[str, Any] = {}
    for key, value in attributes.items():
        if _drop_attribute(str(key)):
            continue
        sanitized[str(key)] = _sanitize_value(str(key), value)
    return sanitized
