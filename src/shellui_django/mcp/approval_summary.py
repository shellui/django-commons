"""One-line summary of a tool call for the person who approves it.

A tool marks the properties that say where a call sends data with ``x-mcp-destination: true`` in its
``inputSchema`` (see ``destinations``). Those values are shown first, in full, under a label built
from the schema path, never from a key the caller chose. Every other value is cut on its own, so no
argument can push another out of view. Nothing here guesses from key names.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from shellui_django.mcp.destinations import (
    CONTAINERS,
    DESTINATION_MARKER,
    ENVELOPE_KEYS,
    declarations,
    destination_paths,
    is_marked,
    properties,
)

__all__ = [
    'ApprovalSummaryRefused',
    'ApprovalSummaryTooLong',
    'DESTINATION_MARKER',
    'destination_paths',
    'mask_url_secrets',
    'summarize_arguments',
]

_OTHER_VALUE_MAX = 60
_KEY_MAX = 40
_RESERVED_FOR_OTHERS = 60
_REMOVED = object()
UNDECLARED_WARNING = 'WARNING: this tool has not declared where it sends data, so check every address in the arguments.'
# ``scheme://userinfo@`` up to the last ``@`` of the authority, which is where a URL parser ends userinfo.
_USERINFO = re.compile(r'([A-Za-z][A-Za-z0-9+.\-]*://)[^/\s?#]*@')
# A ``key=value`` pair of a query string or a fragment: ``?token=...``, ``&X-Amz-Signature=...``, ``#access_token=...``.
_PARAM = re.compile(r'([?&;#])([^=&#;\s"\'?]+)=([^&#;\s"\']*)')
_KEY_TOKENS = re.compile(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+')
# A parameter is a credential when one of its words is one of these (split on punctuation and camelCase), or
# when the whole name, run together, is one of ``_SECRET_NAMES``. ``authurl`` is neither, so it stays visible.
_SECRET_WORDS = frozenset(
    {'token', 'secret', 'signature', 'sig', 'password', 'passwd', 'pwd', 'key', 'code', 'auth', 'authorization',
     'credential', 'credentials', 'apikey', 'jwt', 'bearer', 'assertion', 'otp'}
)
_SECRET_NAMES = frozenset(
    {'accesstoken', 'refreshtoken', 'idtoken', 'authtoken', 'sessiontoken', 'clientsecret', 'apikey', 'accesskey',
     'secretkey', 'privatekey', 'xapikey', 'xauthtoken', 'sessionid'}
)


def _is_secret_param(name: str) -> bool:
    words = [word.lower() for word in _KEY_TOKENS.findall(name)]
    return bool(set(words) & _SECRET_WORDS) or ''.join(words) in _SECRET_NAMES


def _mask_param(match: re.Match[str]) -> str:
    sep, name, value = match.groups()
    return f'{sep}{name}=***' if _is_secret_param(name) else match.group(0)


class ApprovalSummaryRefused(ValueError):
    """The call names destinations the approval line cannot show faithfully. Refuse the call."""


class ApprovalSummaryTooLong(ApprovalSummaryRefused):
    """The destinations do not fit in the line. The call should be refused, not shortened."""


def mask_url_secrets(text: str) -> str:
    """Hide ``user:pass@`` and credential-looking query or fragment parameter values (``?token=...``, ``#access_token=...``)."""
    return _PARAM.sub(_mask_param, _USERINFO.sub(r'\1***@', text))


def _mask_all(value: Any) -> Any:
    if isinstance(value, str):
        return mask_url_secrets(value)
    if isinstance(value, dict):
        return {key: _mask_all(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_all(item) for item in value]
    return value


def _escaped(text: str) -> str:
    """JSON string literal: newlines, control characters and non-ASCII (lookalikes) show as escapes."""
    return json.dumps(text, ensure_ascii=True)


def _fit(text: str, limit: int) -> str:
    """Cut so the escaped form is at most ``limit`` characters, ending in ``...`` when cut."""
    text = ' '.join(text.split())
    if len(_escaped(text)) - 2 <= limit:
        return text
    kept: list[str] = []
    used = 3
    for ch in text:
        width = len(_escaped(ch)) - 2
        if used + width > limit:
            break
        kept.append(ch)
        used += width
    return ''.join(kept).rstrip() + '...'


def _argument_pairs(arguments: dict[str, Any]) -> list[tuple[str | None, str, Any]]:
    """``(section, name, value)`` for every argument the tool would receive, flat or inside a section."""
    pairs: list[tuple[str | None, str, Any]] = []
    for key, value in arguments.items():
        key = str(key)
        if key in ENVELOPE_KEYS:
            continue
        if key in CONTAINERS and isinstance(value, dict):
            pairs.extend((key, str(inner), item) for inner, item in value.items())
        else:
            pairs.append((None, key, value))
    return pairs


def _split(value: Any, node: Any, label: str, marked: bool, out: list[tuple[str, str]]) -> Any:
    """Move the destinations in ``value`` into ``out``. Returns what is left, ``_REMOVED`` when nothing is.

    ``marked`` is inherited: a marked array marks every item. A marked property that receives an
    object, or an array holding objects, cannot be shown faithfully, so the call is refused.
    """
    node = node if isinstance(node, dict) else {}
    # A marker on the items of an array marks the property too: an object or a bare string sent there is a destination.
    marked = marked or is_marked(node) or is_marked(node.get('items'))
    if marked:
        if value is None:
            return _REMOVED
        if isinstance(value, dict):
            raise ApprovalSummaryRefused(f'{label} is a destination and must be text, not an object.')
        if isinstance(value, list):
            items = node.get('items')
            for index, item in enumerate(value):
                _split(item, items, f'{label}[{index}]', True, out)
            return _REMOVED
        out.append((label, str(value)))
        return _REMOVED
    if isinstance(value, dict):
        props = properties(node)
        kept: dict[str, Any] = {}
        removed = False
        for key, item in value.items():
            child = props.get(str(key))
            rest = item if child is None else _split(item, child, f'{label}.{key}', False, out)
            if rest is _REMOVED:
                removed = True
            else:
                kept[key] = rest
        return _REMOVED if removed and not kept else kept
    if isinstance(value, list) and isinstance(node.get('items'), dict):
        kept_items = [_split(item, node['items'], f'{label}[{index}]', False, out) for index, item in enumerate(value)]
        kept_items = [item for item in kept_items if item is not _REMOVED]
        return kept_items if kept_items or not value else _REMOVED
    return value


def _unique(label: str, taken: dict[str, str]) -> str:
    candidate, number = label, 1
    while candidate in taken:
        number += 1
        candidate = f'{label} #{number}'
    return candidate


def summarize_arguments(
    arguments: dict[str, Any] | None,
    input_schema: dict[str, Any] | None,
    max_length: int = 500,
    *,
    destinations_declared: bool = False,
    redact: Callable[[Any], Any] | None = None,
) -> str:
    """The approval line for a call. Raises ``ApprovalSummaryRefused`` (or its ``ApprovalSummaryTooLong``).

    ``arguments`` are the arguments the tool will receive and ``input_schema`` is the tool's
    ``inputSchema``. Destinations are taken out first and never pass through ``redact``, which hides
    secret-looking values in what is left. A caller sending the same name under two sections, or flat,
    is checked against every declaration of that name, so an unmarked ``query.url`` cannot hide a marked
    ``body.url``. ``destinations_declared`` defaults to false (fail closed): the line then starts with a warning, so a caller
    passes true only for a tool whose service declared its destinations.
    """
    if not isinstance(arguments, dict):
        return ''
    declared, sections = declarations(input_schema)
    destinations: dict[str, str] = {}
    others: dict[str, str] = {}
    for section, key, value in _argument_pairs(arguments):
        own = sections[section].get(key) if section else None
        nodes = [own] if own is not None else declared.get(key, [])
        found: list[tuple[str, str]] = []
        rest: Any = value
        for node in nodes:
            part: list[tuple[str, str]] = []
            left = _split(value, node, key, False, part)
            if part:
                found.extend(part)
                rest = left
        for label, text in dict.fromkeys(found):
            destinations[_unique(_fit(label, 120), destinations)] = mask_url_secrets(text)
        if rest is _REMOVED:
            continue
        if redact is not None:
            rest = redact({key: rest})[key]
        text = rest if isinstance(rest, str) else json.dumps(_mask_all(rest), sort_keys=True, default=str, ensure_ascii=True)
        others[_unique(_fit(key, _KEY_MAX), others)] = _fit(mask_url_secrets(text), _OTHER_VALUE_MAX)
    parts: list[str] = []
    if not destinations_declared:
        parts.append(UNDECLARED_WARNING)
    if destinations:
        text = 'Destinations: ' + json.dumps(destinations, ensure_ascii=True)
        if len(text) > max_length - _RESERVED_FOR_OTHERS - len(UNDECLARED_WARNING) * (not destinations_declared):
            raise ApprovalSummaryTooLong(f'The destinations take {len(text)} characters and do not fit in the approval line.')
        parts.append(text)
    if others:
        parts.append('Arguments: ' + json.dumps(others, ensure_ascii=True))
    line = ' | '.join(parts)
    if len(line) > max_length:
        line = line[: max_length - 3].rstrip() + '...'
    return line
