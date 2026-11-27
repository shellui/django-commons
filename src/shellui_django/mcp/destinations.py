"""Destination markers in a tool's ``inputSchema``.

A property that says where a call sends data carries ``x-mcp-destination: true``. The marker is
allowed on a string property, on an array of strings, or on the string items of one, at any depth
under ``properties`` and ``items``. Anywhere else it would be ignored at runtime, so it is refused
when the schema is built (``DestinationMarkerError``) instead.

This module also holds the schema checks a service runs in its contract test:
``destination_paths`` (what is marked) and ``lint_destination_names`` (what looks like a
destination and is not marked).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from typing import Any

DESTINATION_MARKER = 'x-mcp-destination'

# Sections of a tool built by ``tools_from_schema``. A flat schema has the arguments at the top.
CONTAINERS = ('path_params', 'query', 'body')
ENVELOPE_KEYS = frozenset({'path', 'method', 'headers'})

# Names that look like a place data goes to. A write tool with such a field that is neither marked
# nor on the service's allow-list fails ``lint_destination_names``.
_DESTINATION_NAME = re.compile(
    r'(url|uri|host|hostname|email|domain|endpoint|recipient|dsn)s?[_\-]?\d*$'
    r'|redirect|callback|origin|webhook|address|target|href|server|phone|link|destination'
    r'|(^|[_\-.])(to|cc|bcc)$|(reply|send)[_\-]?to',
    re.IGNORECASE,
)
_UNSUPPORTED_KEYS = frozenset(
    {'anyOf', 'oneOf', 'allOf', 'not', 'if', 'then', 'else', 'patternProperties', 'prefixItems', '$ref', 'additionalProperties'}
)


class DestinationMarkerError(ValueError):
    """A schema marks a destination where the approval summary cannot honour it."""


def properties(node: Any) -> dict[str, Any]:
    props = node.get('properties') if isinstance(node, dict) else None
    return props if isinstance(props, dict) else {}


def is_marked(node: Any) -> bool:
    return isinstance(node, dict) and node.get(DESTINATION_MARKER) is True


def declarations(schema: dict[str, Any] | None) -> tuple[dict[str, list[Any]], dict[str, dict[str, Any]]]:
    """``(every node declared under each argument name, nodes per section)`` for a flat or sectioned schema."""
    sections = {section: properties(properties(schema).get(section)) for section in CONTAINERS}
    declared: dict[str, list[Any]] = {}
    for key, node in properties(schema).items():
        if key not in CONTAINERS and key not in ENVELOPE_KEYS:
            declared.setdefault(key, []).append(node)
    for nodes in sections.values():
        for key, node in nodes.items():
            declared.setdefault(key, []).append(node)
    return declared, sections


def destination_paths(input_schema: dict[str, Any] | None) -> set[str]:
    """Dotted argument paths a tool schema marks as destinations (a list is its own path, not ``path[0]``)."""
    found: set[str] = set()

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        items = node.get('items')
        if is_marked(node) or is_marked(items):
            found.add(path)
        for key, child in properties(node).items():
            walk(child, f'{path}.{key}')
        if isinstance(items, dict):
            for key, child in properties(items).items():
                walk(child, f'{path}.{key}')

    for name, nodes in declarations(input_schema)[0].items():
        for node in nodes:
            walk(node, name)
    return found


def _type_names(node: dict[str, Any]) -> set[str]:
    typ = node.get('type')
    return {str(t) for t in typ} - {'null'} if isinstance(typ, list) else {str(typ)}


def _is_string_node(node: Any) -> bool:
    return isinstance(node, dict) and _type_names(node) == {'string'}


def count_markers(node: Any) -> int:
    """Every ``x-mcp-destination`` key anywhere under ``node``: ``$defs``, tuple ``items``, ``contains``,
    ``dependentSchemas``, ``unevaluatedProperties``, headers, path and every other keyword included."""
    if isinstance(node, dict):
        return sum((1 if key == DESTINATION_MARKER else 0) + count_markers(value) for key, value in node.items())
    if isinstance(node, list):
        return sum(count_markers(item) for item in node)
    return 0


def kept_marker_count(node: Any) -> int:
    """Markers the approval summary can read: on ``node``, or reached through ``properties`` and ``items``."""
    if not isinstance(node, dict):
        return 0
    count = 1 if DESTINATION_MARKER in node else 0
    count += sum(kept_marker_count(child) for child in properties(node).values())
    return count + kept_marker_count(node.get('items'))


def readable_marker_count(input_schema: dict[str, Any] | None) -> int:
    """Markers in a tool ``inputSchema`` that the summary reads: under an argument (flat, or in ``path_params``,
    ``query`` or ``body``), never on a section itself, ``path``, ``method`` or ``headers``."""
    return sum(kept_marker_count(node) for nodes in declarations(input_schema)[0].values() for node in nodes)


def validate_destination_schema(input_schema: dict[str, Any], *, tool: str = '') -> None:
    """Raise ``DestinationMarkerError`` when a marker sits where the summary would ignore it.

    The marker must be ``true`` on a string, an array of strings, or the string items of one, reached
    through ``properties`` and ``items`` only, under an argument. Every marker in the schema is counted
    (the same count the OpenAPI build uses) and compared with the markers the summary can read, so a
    placement this module never walks (``$ref`` into ``$defs``, tuple ``items``, ``contains``,
    ``dependentSchemas``, ``unevaluatedProperties``, ``headers``, ``path``, a section node) is refused too.
    """
    where = f' in tool {tool}' if tool else ''

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        if DESTINATION_MARKER in node:
            if node[DESTINATION_MARKER] is not True:
                raise DestinationMarkerError(f'{DESTINATION_MARKER} must be true at {path}{where}')
            items = node.get('items')
            if not (_is_string_node(node) or (isinstance(items, dict) and _type_names(node) == {'array'} and _is_string_node(items))):
                raise DestinationMarkerError(f'{DESTINATION_MARKER} at {path}{where} is not on a string or an array of strings')
        for key in _UNSUPPORTED_KEYS & node.keys():
            if _contains_marker(node[key]):
                raise DestinationMarkerError(f'{DESTINATION_MARKER} under {key} at {path}{where} would be ignored')
        for key, child in properties(node).items():
            walk(child, f'{path}.{key}')
        if isinstance(node.get('items'), dict):
            walk(node['items'], f'{path}[]')

    for name, nodes in declarations(input_schema)[0].items():
        for node in nodes:
            walk(node, name)
    if count_markers(input_schema) != readable_marker_count(input_schema):
        raise DestinationMarkerError(
            f'{DESTINATION_MARKER}{where} sits where the approval summary cannot read it (under $ref or $defs, tuple items, '
            'contains, dependentSchemas, unevaluatedProperties, headers, path, or on a section). Mark a plain argument instead.'
        )


def _contains_marker(value: Any) -> bool:
    if isinstance(value, dict):
        return DESTINATION_MARKER in value or any(_contains_marker(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_marker(item) for item in value)
    return False


def lint_destination_names(
    tools: list[dict[str, Any]],
    allow: Mapping[str, Collection[str]] | None = None,
) -> list[str]:
    """Problems for a service's contract test; an empty list passes.

    Every string (or list of strings) argument of a write tool whose name looks like a destination
    (``*url``, ``*uri``, ``*host``, ``*email``, ``*domain``, ``*origin*``, ``redirect*``, ``callback*``,
    ``*endpoint``, ``*recipient``) must be marked with ``x-mcp-destination`` or listed in ``allow``,
    a mapping of tool name to the dotted paths that were reviewed and are not destinations. A stale
    allow-list entry (no such field, or a marked one) is also a problem, so the list stays honest.
    Read-only tools send nothing and are not checked.
    """
    allow = allow or {}
    problems: list[str] = []
    seen_allowed: set[tuple[str, str]] = set()
    for tool in tools:
        name = str(tool.get('name'))
        read_only = bool((tool.get('_meta') or {}).get('read_only'))
        marked = destination_paths(tool.get('inputSchema'))
        allowed = set(allow.get(name, ()))
        candidates: set[str] = set()

        def walk(node: Any, path: str, candidates: set[str] = candidates) -> None:
            if not isinstance(node, dict):
                return
            leaf = node.get('items') if isinstance(node.get('items'), dict) and _type_names(node) == {'array'} else node
            if _is_string_node(leaf) and _DESTINATION_NAME.search(path.rsplit('.', 1)[-1]):
                candidates.add(path)
            for key, child in properties(node).items():
                walk(child, f'{path}.{key}', candidates)
            if isinstance(node.get('items'), dict):
                for key, child in properties(node['items']).items():
                    walk(child, f'{path}.{key}', candidates)

        for key, nodes in declarations(tool.get('inputSchema'))[0].items():
            for node in nodes:
                walk(node, key)
        for path in sorted(candidates - marked):
            if not read_only and path not in allowed:
                problems.append(f'{name}: {path} looks like a destination but is not marked {DESTINATION_MARKER} or allow-listed')
        for path in sorted(allowed):
            seen_allowed.add((name, path))
            if path not in candidates or path in marked:
                problems.append(f'{name}: allow-list entry {path} is stale (not a candidate, or already marked)')
    for name, paths in allow.items():
        for path in paths:
            if (name, path) not in seen_allowed:
                problems.append(f'{name}: allow-list entry {path} names a tool that is not published')
    return problems
