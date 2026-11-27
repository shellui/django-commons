"""One-line summary of a tool call for the person who approves it.

A tool marks the properties that say where a call sends data with ``x-mcp-destination: true`` in its
``inputSchema`` (also on nested properties and array items). Those values are shown first, in full,
under a label built from the schema path, never from a key the caller chose. Every other value is
cut on its own, so no argument can push another out of view. Nothing here guesses from key names.
"""

from __future__ import annotations

import json
import re
from typing import Any

from shellui_django.mcp.openapi_tools import DESTINATION_MARKER

# Keys the gateway fills in itself, or that never reach the tool as an argument.
_ENVELOPE_KEYS = frozenset({'path', 'method', 'headers'})
_CONTAINERS = ('path_params', 'query', 'body')
_OTHER_VALUE_MAX = 60
_KEY_MAX = 40
_RESERVED_FOR_OTHERS = 60
_REMOVED = object()
# ``scheme://userinfo@`` up to the last ``@`` of the authority, which is where a URL parser ends userinfo.
_USERINFO = re.compile(r'([A-Za-z][A-Za-z0-9+.\-]*://)[^/\s?#]*@')


class ApprovalSummaryTooLong(ValueError):
    """The destinations do not fit in the line. The call should be refused, not shortened."""


def mask_userinfo(text: str) -> str:
    """Replace ``user:pass@`` in every URL in ``text`` with ``***@``."""
    return _USERINFO.sub(r'\1***@', text)


def _mask_all(value: Any) -> Any:
    if isinstance(value, str):
        return mask_userinfo(value)
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


def _properties(node: Any) -> dict[str, Any]:
    props = node.get('properties') if isinstance(node, dict) else None
    return props if isinstance(props, dict) else {}


def _schema_fields(schema: dict[str, Any] | None) -> dict[str, Any]:
    """Argument name to schema node, whether the schema is flat or has ``query``/``body`` sections."""
    fields = {k: v for k, v in _properties(schema).items() if k not in _CONTAINERS and k not in _ENVELOPE_KEYS}
    for section in _CONTAINERS:
        for key, node in _properties(_properties(schema).get(section)).items():
            fields.setdefault(key, node)
    return fields


def _argument_pairs(arguments: dict[str, Any]) -> list[tuple[str, Any]]:
    """Every argument the tool would receive, whether sent flat or inside ``query``/``body``/``path_params``."""
    pairs: list[tuple[str, Any]] = []
    for key, value in arguments.items():
        key = str(key)
        if key in _ENVELOPE_KEYS:
            continue
        if key in _CONTAINERS and isinstance(value, dict):
            pairs.extend((str(inner), item) for inner, item in value.items())
        else:
            pairs.append((key, value))
    return pairs


def _is_marked(node: Any) -> bool:
    return isinstance(node, dict) and node.get(DESTINATION_MARKER) is True


def _collect(value: Any, node: Any, label: str, out: list[tuple[str, str]]) -> None:
    if not isinstance(node, dict):
        return
    if _is_marked(node) and not isinstance(node.get('items'), dict):
        if isinstance(value, (dict, list)) or value is None:
            return
        out.append((label, str(value)))
        return
    if isinstance(value, dict):
        props = _properties(node)
        for key, item in value.items():
            if str(key) in props:
                _collect(item, props[str(key)], f'{label}.{key}', out)
    elif isinstance(value, list) and isinstance(node.get('items'), dict):
        for index, item in enumerate(value):
            _collect(item, node['items'], f'{label}[{index}]', out)


def destination_paths(input_schema: dict[str, Any] | None) -> set[str]:
    """Dotted argument paths a tool schema marks as destinations (a list is its own path, not ``path[0]``).

    Services use it in tests to pin which fields of each tool carry ``x-mcp-destination``.
    """
    found: set[str] = set()

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        items = node.get('items')
        if _is_marked(node) or _is_marked(items):
            found.add(path)
        for key, child in _properties(node).items():
            walk(child, f'{path}.{key}')
        if isinstance(items, dict):
            for key, child in _properties(items).items():
                walk(child, f'{path}.{key}')

    for name, node in _schema_fields(input_schema).items():
        walk(node, name)
    return found


def _without_destinations(value: Any, node: Any) -> Any:
    """``value`` with every destination leaf removed, ``_REMOVED`` when nothing is left."""
    if not isinstance(node, dict):
        return value
    if _is_marked(node) and not isinstance(node.get('items'), dict):
        return _REMOVED
    if isinstance(value, dict):
        props = _properties(node)
        kept = {}
        had_destination = False
        for key, item in value.items():
            rest = _without_destinations(item, props.get(str(key)))
            if rest is _REMOVED:
                had_destination = True
            else:
                kept[key] = rest
        return _REMOVED if had_destination and not kept else kept
    if isinstance(value, list) and isinstance(node.get('items'), dict):
        kept_items = [_without_destinations(item, node['items']) for item in value]
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
) -> str:
    """The approval line for a call. Raises ``ApprovalSummaryTooLong`` when the destinations do not fit.

    ``arguments`` are the arguments the tool will receive, with secrets already masked, and
    ``input_schema`` is the tool's ``inputSchema``. Without ``x-mcp-destination`` markers every value
    is shown as an ordinary argument, still with ``user:pass@`` masked and each value cut on its own.
    """
    if not isinstance(arguments, dict):
        return ''
    fields = _schema_fields(input_schema)
    destinations: dict[str, str] = {}
    others: dict[str, str] = {}
    for key, value in _argument_pairs(arguments):
        node = fields.get(key)
        found: list[tuple[str, str]] = []
        _collect(value, node, key, found)
        for label, text in found:
            destinations[_unique(_fit(label, 120), destinations)] = mask_userinfo(text)
        rest = _without_destinations(value, node) if found else value
        if rest is _REMOVED:
            continue
        text = rest if isinstance(rest, str) else json.dumps(_mask_all(rest), sort_keys=True, default=str, ensure_ascii=True)
        others[_unique(_fit(key, _KEY_MAX), others)] = _fit(mask_userinfo(text), _OTHER_VALUE_MAX)
    parts: list[str] = []
    if destinations:
        text = 'Destinations: ' + json.dumps(destinations, ensure_ascii=True)
        if len(text) > max_length - _RESERVED_FOR_OTHERS:
            raise ApprovalSummaryTooLong(
                f'The destinations take {len(text)} characters, more than the {max_length - _RESERVED_FOR_OTHERS} allowed.'
            )
        parts.append(text)
    if others:
        parts.append('Arguments: ' + json.dumps(others, ensure_ascii=True))
    line = ' | '.join(parts)
    if len(line) > max_length:
        line = line[: max_length - 3].rstrip() + '...'
    return line
