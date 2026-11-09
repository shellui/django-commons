"""Build MCP tool definitions from a drf-spectacular OpenAPI schema."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from shellui_django.mcp.openapi_mcp import tool_access_flags
from shellui_django.mcp.routing import path_parameter_names

MCP_TOOL_TAG = 'mcp-tools'


def _components(root: dict[str, Any]) -> dict[str, Any]:
    return (root.get('components') or {}).get('schemas') or {}


def _resolve_schema(
    schema: dict[str, Any] | None,
    root: dict[str, Any],
    *,
    _seen: frozenset[str] | None = None,
) -> dict[str, Any]:
    if not schema or not isinstance(schema, dict):
        return {}
    ref = schema.get('$ref')
    if isinstance(ref, str) and ref.startswith('#/components/schemas/'):
        name = ref.rsplit('/', 1)[-1]
        seen = _seen or frozenset()
        if name in seen:
            return {
                'type': 'object',
                'additionalProperties': True,
                'description': f'Circular $ref: {ref}',
            }
        target = _components(root).get(name)
        if isinstance(target, dict):
            return _resolve_schema(deepcopy(target), root, _seen=seen | {name})
        return {}
    if '$ref' in schema and len(schema) > 1:
        resolved = _resolve_schema({'$ref': schema['$ref']}, root, _seen=_seen)
        return {**resolved, **{k: v for k, v in schema.items() if k != '$ref'}}
    return schema


_SCALAR_TYPES = frozenset({'string', 'integer', 'number', 'boolean'})


def _free_form(description: str | None = None) -> dict[str, Any]:
    return {'type': 'object', 'additionalProperties': True, 'description': description or 'JSON value'}


def _is_null_variant(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    if node.get('type') == 'null':
        return True
    enum = node.get('enum')
    return isinstance(enum, list) and len(enum) > 0 and all(v is None for v in enum)


def _enum_type(values: list[Any]) -> str | None:
    non_null = [v for v in values if v is not None]
    if not non_null:
        return None
    if all(isinstance(v, bool) for v in non_null):
        return 'boolean'
    if all(isinstance(v, int) and not isinstance(v, bool) for v in non_null):
        return 'integer'
    if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in non_null):
        return 'number'
    if all(isinstance(v, str) for v in non_null):
        return 'string'
    return None


def _flatten(node: dict[str, Any], root: dict[str, Any], seen: frozenset[str]) -> tuple[dict[str, Any], frozenset[str], bool]:
    """Resolve ``$ref`` and single-schema ``allOf`` / ``oneOf`` / ``anyOf`` wrappers.

    Returns the flattened node, the refs visited, and whether null is allowed.
    """
    nullable = bool(node.get('nullable'))
    for _ in range(32):
        ref = node.get('$ref')
        if isinstance(ref, str):
            name = ref.rsplit('/', 1)[-1]
            target = _components(root).get(name) if ref.startswith('#/components/schemas/') else None
            if name in seen or not isinstance(target, dict):
                return _free_form(f'Unresolved $ref: {ref}'), seen, nullable
            seen = seen | {name}
            siblings = {k: v for k, v in node.items() if k != '$ref'}
            node = {**deepcopy(target), **siblings}
            nullable = nullable or bool(node.get('nullable'))
            continue
        all_of = node.get('allOf')
        if isinstance(all_of, list) and all_of:
            siblings = {k: v for k, v in node.items() if k != 'allOf'}
            merged: dict[str, Any] = {}
            props: dict[str, Any] = {}
            required: list[Any] = []
            for part in all_of:
                if not isinstance(part, dict):
                    continue
                flat, seen, part_null = _flatten(part, root, seen)
                nullable = nullable or part_null
                props.update(flat.get('properties') or {})
                required.extend(flat.get('required') or [])
                merged.update({k: v for k, v in flat.items() if k not in {'properties', 'required'}})
            if props:
                merged['properties'] = props
            if required:
                merged['required'] = required
            node = {**merged, **siblings}
            continue
        for key in ('oneOf', 'anyOf'):
            variants = node.get(key)
            if not isinstance(variants, list) or not variants:
                continue
            siblings = {k: v for k, v in node.items() if k != key}
            kept: list[dict[str, Any]] = []
            for variant in variants:
                if not isinstance(variant, dict):
                    continue
                flat, seen, var_null = _flatten(variant, root, seen)
                if _is_null_variant(flat):
                    nullable = True
                    continue
                nullable = nullable or var_null
                kept.append(flat)
            if len(kept) == 1:
                node = {**kept[0], **siblings}
            elif kept and all(isinstance(v.get('enum'), list) for v in kept):
                # drf-spectacular: oneOf [StatusEnum, BlankEnum, NullEnum].
                values: list[Any] = []
                for v in kept:
                    values.extend(x for x in v['enum'] if x not in values)
                node = {'enum': values, **siblings}
            else:
                return _free_form(siblings.get('description')), seen, nullable
            break
        else:
            return node, seen, nullable
    return _free_form(node.get('description')), seen, nullable


def _client_prop_schema(
    node: Any,
    root: dict[str, Any] | None = None,
    _seen: frozenset[str] | None = None,
) -> dict[str, Any]:
    """JSON Schema fragment safe for strict MCP clients."""
    if not isinstance(node, dict):
        return {'type': 'string'}
    root = root or {}
    node, seen, nullable = _flatten(node, root, _seen or frozenset())
    out: dict[str, Any] = {}
    if node.get('description'):
        out['description'] = str(node['description'])
    typ = node.get('type')
    if isinstance(typ, list):
        if 'null' in typ:
            nullable = True
        non_null = [t for t in typ if t != 'null']
        typ = non_null[0] if non_null else None
    enum = node.get('enum') if isinstance(node.get('enum'), list) else None
    if enum is not None:
        if None in enum:
            nullable = True
        enum = [v for v in enum if v is not None]
        typ = typ or _enum_type(enum)
    if typ in _SCALAR_TYPES:
        out['type'] = [typ, 'null'] if nullable else typ
        if typ == 'string' and node.get('format'):
            out['format'] = str(node['format'])
        if enum:
            out['enum'] = enum + [None] if nullable else enum
        return out
    if typ == 'array':
        out['type'] = ['array', 'null'] if nullable else 'array'
        items = node.get('items')
        out['items'] = _client_prop_schema(items if isinstance(items, dict) else {'type': 'string'}, root, seen)
        return out
    if typ == 'object' or isinstance(node.get('properties'), dict):
        out['type'] = ['object', 'null'] if nullable else 'object'
        props = node.get('properties') if isinstance(node.get('properties'), dict) else {}
        out['properties'] = {str(k): _client_prop_schema(v, root, seen) for k, v in props.items()}
        # Named props stay closed; empty object schemas (JSONField) stay open.
        out['additionalProperties'] = bool(node.get('additionalProperties', False)) if props else True
        req = node.get('required')
        if isinstance(req, list):
            required = [str(k) for k in req if str(k) in out['properties']]
            if required:
                out['required'] = required
        return out
    # drf-spectacular JSONField often emits ``{}`` or description-only nodes.
    out['type'] = 'object'
    out['additionalProperties'] = True
    if not out.get('description'):
        out['description'] = 'JSON value'
    return out


def _parameter_schemas(
    operation: dict[str, Any],
    root: dict[str, Any],
    *,
    location: str,
) -> tuple[dict[str, Any], list[str]]:
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('in') != location:
            continue
        name = param.get('name')
        if not name:
            continue
        key = str(name)
        raw = param.get('schema') if isinstance(param.get('schema'), dict) else {'type': 'string'}
        properties[key] = _client_prop_schema(raw if isinstance(raw, dict) else {}, root)
        if param.get('required'):
            required.append(key)
    return properties, required


def _body_schemas(operation: dict[str, Any], root: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    request_body = operation.get('requestBody') or {}
    if not isinstance(request_body, dict):
        return {}, []
    content = request_body.get('content') or {}
    schema = content.get('application/json', {}).get('schema') or {}
    if not isinstance(schema, dict):
        return {}, []
    resolved = _resolve_schema(schema, root)
    props = resolved.get('properties') or {}
    if not isinstance(props, dict):
        return {}, []
    properties = {str(key): _client_prop_schema(val, root) for key, val in props.items()}
    required_raw = resolved.get('required') or []
    required = [str(key) for key in required_raw if str(key) in properties]
    return properties, required


def _slug_tool_name(method: str, path: str, operation_id: str | None) -> str:
    if operation_id:
        base = re.sub(r'[^a-zA-Z0-9_]+', '_', operation_id).strip('_').lower()
        if base:
            return base[:120]
    cleaned = re.sub(r'[^a-zA-Z0-9_]+', '_', f'{method}_{path}').strip('_').lower()
    return cleaned[:120]


def tools_from_schema(schema: dict[str, Any]) -> list[dict[str, Any]]:
    paths = schema.get('paths') or {}
    tools: list[dict[str, Any]] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {'get', 'post', 'put', 'patch', 'delete'}:
                continue
            if not isinstance(operation, dict):
                continue
            tags = operation.get('tags') or []
            if MCP_TOOL_TAG not in tags:
                continue
            name = _slug_tool_name(method, path, operation.get('operationId'))
            description = (operation.get('summary') or operation.get('description') or name).strip()
            path_params = path_parameter_names(path)
            query_props, query_required = _parameter_schemas(operation, schema, location='query')
            body_props, body_required = _body_schemas(operation, schema)
            properties: dict[str, Any] = {
                'path': {'type': 'string', 'const': path},
                'method': {'type': 'string', 'enum': [method.upper()]},
                'query': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': query_props,
                },
                'body': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': body_props,
                },
            }
            if query_required:
                properties['query']['required'] = query_required
            if body_required:
                properties['body']['required'] = body_required
            required = ['path', 'method']
            if path_params:
                properties['path_params'] = {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {param: {'type': 'string'} for param in path_params},
                    'required': path_params,
                }
                required.append('path_params')
            access = tool_access_flags(operation)
            tools.append(
                {
                    'name': name,
                    'description': description,
                    'inputSchema': {
                        'type': 'object',
                        'properties': properties,
                        'required': required,
                        'additionalProperties': False,
                    },
                    '_meta': {
                        'path': path,
                        'method': method.upper(),
                        'operationId': operation.get('operationId'),
                        'path_params': path_params,
                        'query_fields': sorted(query_props.keys()) or None,
                        'query_required': query_required or None,
                        'body_fields': sorted(body_props.keys()) or None,
                        'body_required': body_required or None,
                        'read_only': access['read_only'],
                        'destructive': access['destructive'],
                        'mcp_tagged': access['tagged'],
                    },
                }
            )
    tools.sort(key=lambda t: t['name'])
    return tools
