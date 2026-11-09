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


def _client_prop_schema(node: Any) -> dict[str, Any]:
    """JSON Schema fragment safe for strict MCP clients."""
    if not isinstance(node, dict):
        return {'type': 'string'}
    out: dict[str, Any] = {}
    if node.get('description'):
        out['description'] = str(node['description'])
    typ = node.get('type')
    if isinstance(typ, list):
        non_null = [t for t in typ if t != 'null']
        typ = non_null[0] if non_null else 'string'
    if typ in {'string', 'integer', 'number', 'boolean'}:
        out['type'] = typ
        if typ == 'string' and node.get('format'):
            out['format'] = str(node['format'])
        return out
    if typ == 'array':
        out['type'] = 'array'
        items = node.get('items')
        out['items'] = _client_prop_schema(items if isinstance(items, dict) else {'type': 'string'})
        return out
    if typ == 'object' or isinstance(node.get('properties'), dict):
        out['type'] = 'object'
        props = node.get('properties') if isinstance(node.get('properties'), dict) else {}
        out['properties'] = {str(k): _client_prop_schema(v) for k, v in props.items()}
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
        properties[key] = _client_prop_schema(_resolve_schema(raw if isinstance(raw, dict) else {}, root))
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
    properties = {str(key): _client_prop_schema(val) for key, val in props.items()}
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
