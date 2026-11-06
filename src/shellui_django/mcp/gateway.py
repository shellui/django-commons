"""Aggregated MCP gateway: merge downstream ``tools/list`` and forward ``tools/call``."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import requests
from django.core.cache import cache as django_cache
from django.http import HttpRequest, JsonResponse

from shellui_django.mcp.openapi_tools import tools_from_schema
from shellui_django.mcp.rate_limit import check_agent_rate_limit
from shellui_django.mcp.server import McpServer

logger = logging.getLogger(__name__)

_TOOLS_CACHE_PREFIX = 'mcp_gateway:tools:'
_TOOL_ROUTE_PREFIX = 'mcp_gateway:route:'


class _CacheBackend(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...

    def set(self, key: str, value: Any, timeout: int | float | None = None) -> Any: ...


class _AgentRecord(Protocol):
    services_allowed: list[str] | None


def scope_service_ids(agent_claims: dict[str, Any]) -> set[str]:
    return {part for part in str(agent_claims.get('scope') or '').split() if part}


def service_allowed(agent_services: list[str] | None, service_id: str) -> bool:
    allowed = {str(s) for s in (agent_services or [])}
    return service_id in allowed


def public_mcp_tools(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tool in raw:
        if not isinstance(tool, dict):
            continue
        out.append({k: v for k, v in tool.items() if not str(k).startswith('_')})
    return out


def merge_tool_catalog(
    local_tools: list[dict[str, Any]],
    remote_by_service: dict[str, list[dict[str, Any]]],
    *,
    local_service_id: str,
    remember_route: Callable[[str, str, str], None],
) -> list[dict[str, Any]]:
    taken: set[str] = set()
    merged: list[dict[str, Any]] = []

    for tool in local_tools:
        name = str(tool.get('name') or '')
        if not name:
            continue
        taken.add(name)
        remember_route(name, local_service_id, name)
        merged.append(tool)

    for service_id, tools in remote_by_service.items():
        for tool in tools:
            downstream_name = str(tool.get('name') or '')
            if not downstream_name:
                continue
            export_name = downstream_name
            if export_name in taken:
                export_name = f'{service_id}__{downstream_name}'
            if export_name in taken:
                export_name = f'{service_id}__{downstream_name}__gateway'
            taken.add(export_name)
            remember_route(export_name, service_id, downstream_name)
            if export_name == downstream_name:
                merged.append(tool)
            else:
                merged.append({**tool, 'name': export_name})
    return merged


def gateway_instructions(
    agent_claims: dict[str, Any],
    *,
    agent: _AgentRecord | None,
    service_urls: dict[str, str],
    title: str,
) -> str:
    scope = scope_service_ids(agent_claims)
    allowed_rows = set(agent.services_allowed or []) if agent else set()
    connected = sorted(sid for sid in scope if sid in allowed_rows and sid in service_urls)
    return (
        f'{title}\n'
        f'Connected services: {", ".join(connected) or "none"}.\n'
        'Remote tools run on the downstream service with the same agent access level and approvals.\n'
        'Use the list_services tool for per-service MCP URLs and resource-bound tokens.'
    )


@dataclass(frozen=True, slots=True)
class McpGatewayConfig:
    """Host-injected gateway wiring (service map, agent lookup, downstream tokens)."""

    get_service_urls: Callable[[], dict[str, str]]
    resolve_agent: Callable[[dict[str, Any]], _AgentRecord | None]
    mint_downstream_token: Callable[[_AgentRecord, str], str]
    local_service_id: str
    tools_cache_ttl_seconds: int = 30
    downstream_timeout_seconds: float = 5.0
    instructions_title: str = 'Shellui MCP gateway.'
    cache: _CacheBackend | None = None


class AggregatingMcpServer(McpServer):
    """MCP server that aggregates downstream ``tools/list`` and forwards ``tools/call``."""

    def __init__(self, *, gateway: McpGatewayConfig, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._gateway = gateway

    def _cache(self) -> _CacheBackend:
        return self._gateway.cache or django_cache

    def _remember_route(self, export_name: str, service_id: str, downstream_name: str) -> None:
        self._cache().set(
            f'{_TOOL_ROUTE_PREFIX}{export_name}',
            {'service_id': service_id, 'downstream_name': downstream_name},
            self._gateway.tools_cache_ttl_seconds,
        )

    def _lookup_route(self, tool_name: str) -> dict[str, str] | None:
        meta = self._cache().get(f'{_TOOL_ROUTE_PREFIX}{tool_name}')
        if isinstance(meta, dict) and meta.get('service_id') and meta.get('downstream_name'):
            return {'service_id': str(meta['service_id']), 'downstream_name': str(meta['downstream_name'])}
        return None

    def _fetch_remote_tools_list(self, *, mcp_url: str, bearer_token: str) -> list[dict[str, Any]] | None:
        cache_key = f'{_TOOLS_CACHE_PREFIX}{mcp_url}'
        cached = self._cache().get(cache_key)
        if isinstance(cached, list):
            return cached
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}
        try:
            response = requests.post(
                mcp_url,
                json=payload,
                headers={
                    'Authorization': f'Bearer {bearer_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                timeout=self._gateway.downstream_timeout_seconds,
            )
        except (requests.RequestException, OSError) as exc:
            logger.warning('MCP gateway tools/list transport error url=%s err=%s', mcp_url, type(exc).__name__)
            return None
        if response.status_code >= 400:
            logger.warning('MCP gateway tools/list HTTP %s url=%s', response.status_code, mcp_url)
            return None
        try:
            body = response.json()
        except ValueError:
            logger.warning('MCP gateway tools/list invalid JSON url=%s', mcp_url)
            return None
        tools = (body.get('result') or {}).get('tools')
        if not isinstance(tools, list):
            logger.warning('MCP gateway tools/list missing tools url=%s', mcp_url)
            return None
        public = public_mcp_tools(tools)
        self._cache().set(cache_key, public, self._gateway.tools_cache_ttl_seconds)
        return public

    def handle(self, request: HttpRequest, *, agent_claims: dict[str, Any] | None) -> JsonResponse:
        if request.method != 'POST':
            return JsonResponse({'error': 'method_not_allowed'}, status=405)
        if agent_claims is None:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        agent_id = str(agent_claims.get('agent_id') or '')
        if not agent_id:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        if check_agent_rate_limit(agent_id):
            return JsonResponse({'error': 'rate_limited'}, status=429)
        company_id = agent_claims.get('company_id')
        try:
            company_id_int = int(company_id) if company_id is not None else None
        except (TypeError, ValueError):
            company_id_int = None
        if self.identity_revocation_check and self.identity_revocation_check(agent_id, company_id_int):
            return JsonResponse({'error': 'agent_revoked'}, status=403)
        if not self._service_allowed(agent_claims, self.service_name):
            return JsonResponse({'error': 'forbidden'}, status=403)
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'invalid_json'}, status=400)
        method = payload.get('method')
        req_id = payload.get('id')
        params = payload.get('params') or {}
        if method == 'initialize':
            agent = self._gateway.resolve_agent(agent_claims)
            urls = self._gateway.get_service_urls()
            return JsonResponse(
                self._result(
                    req_id,
                    {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {'tools': {}},
                        'instructions': gateway_instructions(
                            agent_claims,
                            agent=agent,
                            service_urls=urls,
                            title=self._gateway.instructions_title,
                        ),
                    },
                )
            )
        if method == 'tools/list':
            return self._aggregated_tools_list(req_id, agent_claims)
        if method == 'tools/call':
            forwarded = self._maybe_forward_tool_call(request, req_id, params, agent_claims)
            if forwarded is not None:
                return forwarded
        return super().handle(request, agent_claims=agent_claims)

    def _aggregated_tools_list(self, req_id: Any, agent_claims: dict[str, Any]) -> JsonResponse:
        agent = self._gateway.resolve_agent(agent_claims)
        if agent is None:
            return JsonResponse(self._error(req_id, -32603, 'Forbidden'))
        scope = scope_service_ids(agent_claims)
        allowed = scope & set(agent.services_allowed or [])
        schema = self.schema_provider()
        local = public_mcp_tools(tools_from_schema(schema))
        remote: dict[str, list[dict[str, Any]]] = {}
        urls = self._gateway.get_service_urls()
        local_id = self._gateway.local_service_id
        for service_id, mcp_url in urls.items():
            if service_id == local_id:
                continue
            if service_id not in allowed:
                continue
            token = self._gateway.mint_downstream_token(agent, mcp_url)
            tools = self._fetch_remote_tools_list(mcp_url=mcp_url, bearer_token=token)
            if tools is not None:
                remote[service_id] = tools

        def remember(export_name: str, sid: str, downstream_name: str) -> None:
            self._remember_route(export_name, sid, downstream_name)

        tools = merge_tool_catalog(
            local,
            remote,
            local_service_id=local_id,
            remember_route=remember,
        )
        return JsonResponse(self._result(req_id, {'tools': tools}))

    def _maybe_forward_tool_call(
        self,
        request: HttpRequest,
        req_id: Any,
        params: dict[str, Any],
        agent_claims: dict[str, Any],
    ) -> JsonResponse | None:
        tool_name = str(params.get('name') or '')
        if not tool_name:
            return None
        route = self._lookup_route(tool_name)
        local_id = self._gateway.local_service_id
        if route is None:
            schema = self.schema_provider()
            local_names = {str(t.get('name')) for t in tools_from_schema(schema)}
            if tool_name in local_names:
                return None
            return JsonResponse(self._error(req_id, -32602, 'Unknown tool'))
        service_id = route['service_id']
        if service_id == local_id:
            return None
        scope = scope_service_ids(agent_claims)
        if not service_allowed(list(scope), service_id):
            return JsonResponse(self._error(req_id, -32602, 'Forbidden'))
        agent = self._gateway.resolve_agent(agent_claims)
        if agent is None or not service_allowed(agent.services_allowed or [], service_id):
            return JsonResponse(self._error(req_id, -32602, 'Forbidden'))
        mcp_url = self._gateway.get_service_urls().get(service_id)
        if not mcp_url:
            return JsonResponse(self._error(req_id, -32602, 'Service unavailable'))
        token = self._gateway.mint_downstream_token(agent, mcp_url)
        downstream_params = dict(params)
        downstream_params['name'] = route['downstream_name']
        rpc = {
            'jsonrpc': '2.0',
            'id': req_id,
            'method': 'tools/call',
            'params': downstream_params,
        }
        try:
            response = requests.post(
                mcp_url,
                json=rpc,
                headers={
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                timeout=self._gateway.downstream_timeout_seconds,
            )
        except (requests.RequestException, OSError) as exc:
            logger.warning(
                'MCP gateway tools/call transport error service=%s tool=%s err=%s',
                service_id,
                tool_name,
                type(exc).__name__,
            )
            return JsonResponse(
                self._result(
                    req_id,
                    {
                        'content': [{'type': 'text', 'text': 'Downstream service unavailable.'}],
                        'isError': True,
                    },
                )
            )
        if response.status_code >= 400:
            logger.warning(
                'MCP gateway tools/call HTTP %s service=%s tool=%s',
                response.status_code,
                service_id,
                tool_name,
            )
            return JsonResponse(
                self._result(
                    req_id,
                    {
                        'content': [{'type': 'text', 'text': 'Downstream service error.'}],
                        'isError': True,
                    },
                )
            )
        try:
            body = response.json()
        except ValueError:
            return JsonResponse(
                self._result(
                    req_id,
                    {'content': [{'type': 'text', 'text': 'Invalid downstream response.'}], 'isError': True},
                )
            )
        if not isinstance(body, dict):
            return JsonResponse(self._error(req_id, -32603, 'Invalid downstream response'))
        return JsonResponse(body)
