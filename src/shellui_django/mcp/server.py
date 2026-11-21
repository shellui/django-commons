"""Streamable HTTP MCP endpoint handler (JSON-RPC over POST /mcp)."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import Any

from django.http import HttpRequest, JsonResponse
from rest_framework.test import APIRequestFactory, force_authenticate

from shellui_django.mcp.identity_jwks import (
    IdentityJwksError,
    decode_identity_rs256_jwt,
    jwt_unix_timestamp_claim_strict,
)
from shellui_django.mcp.masking import redact_mapping
from shellui_django.mcp.openapi_mcp import marker_tree_for_operation_request, marker_tree_for_operation_response
from shellui_django.mcp.openapi_tools import tools_from_schema
from shellui_django.mcp.rate_limit import check_agent_rate_limit
from shellui_django.mcp.resources import access_token_audience_matches
from shellui_django.mcp.routing import (
    McpToolArgumentError,
    materialize_openapi_path,
    tool_arguments_match_company,
    validate_mcp_tool_arguments,
)
from shellui_django.mcp.write_gate import WriteGateDecision, decide_write, is_destructive_operation

logger = logging.getLogger(__name__)

_BODYLESS_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})


class VerifiedTokenUser:
    """Authenticated principal for the bearer token checked in ``McpServer.handle``."""

    is_authenticated = True
    is_anonymous = False
    is_active = True

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.pk = agent_id
        self.id = agent_id

    def __str__(self) -> str:
        return self.agent_id


def _strict_company_id(value: Any) -> int:
    """Non-negative company id. Rejects bool and float so values are not coerced."""
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError
    if isinstance(value, int):
        if value < 0:
            raise ValueError
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    raise ValueError


def _claim_company_id(agent_claims: dict[str, Any]) -> int | None:
    if 'company_id' not in agent_claims or agent_claims.get('company_id') is None:
        return None
    return _strict_company_id(agent_claims['company_id'])


def _delegated_approval_covers(agent_claims: dict[str, Any], tool_name: str) -> bool:
    """True when ``mcp_gateway_delegated`` names this tool and has not expired.

    The claim must be an object ``{"action": "<tool name>", "exp": <unix seconds>}``.
    A boolean or any other shape does not skip approval.
    """
    claim = agent_claims.get('mcp_gateway_delegated')
    if not isinstance(claim, dict):
        return False
    action = claim.get('action')
    if not isinstance(action, str) or not action or action != tool_name:
        return False
    try:
        exp = jwt_unix_timestamp_claim_strict(claim.get('exp'), field='exp')
    except IdentityJwksError:
        return False
    return exp > int(time.time())


def _tool_list_row(tool: dict[str, Any]) -> dict[str, Any]:
    """Public tools/list row: drop private ``_`` keys except registry ``_meta``."""
    row = {k: v for k, v in tool.items() if not str(k).startswith('_')}
    meta = tool.get('_meta')
    if isinstance(meta, dict):
        row['_meta'] = meta
    return row


class McpServer:
    def __init__(
        self,
        *,
        schema_provider: Callable[[], dict[str, Any]],
        urlconf: str,
        service_name: str,
        identity_revocation_check: Callable[[str, int | None], bool] | None = None,
        on_call: Callable[[dict[str, Any]], None] | None = None,
        approval_handler: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
        approval_state: Callable[[dict[str, Any]], str | None] | None = None,
        approval_consume: Callable[..., bool] | None = None,
        identity_issuer: str | None = None,
        identity_jwks_url: str | None = None,
        identity_jwks: dict[str, Any] | None = None,
        mcp_audience: str | None = None,
    ):
        self.schema_provider = schema_provider
        self.urlconf = urlconf
        self.service_name = service_name
        self.identity_revocation_check = identity_revocation_check
        self.on_call = on_call
        self.approval_handler = approval_handler
        self.approval_state = approval_state
        self.approval_consume = approval_consume
        self.identity_issuer = identity_issuer
        self.identity_jwks_url = identity_jwks_url
        self.identity_jwks = identity_jwks
        self.mcp_audience = mcp_audience
        self._factory = APIRequestFactory()

    def handle(self, request: HttpRequest, *, agent_claims: dict[str, Any] | None = None) -> JsonResponse:
        """Dispatch one MCP JSON-RPC request.

        ``agent_claims`` is accepted so existing callers keep working. Authorization
        uses the verified bearer token only.
        """
        del agent_claims
        prepared = self._prepare(request)
        if isinstance(prepared, JsonResponse):
            return prepared
        return self._handle_prepared(request, prepared)

    def _prepare(self, request: HttpRequest) -> dict[str, Any] | JsonResponse:
        if request.method != 'POST':
            return JsonResponse({'error': 'method_not_allowed'}, status=405)
        agent_claims = self._claims_from_bearer(request)
        if agent_claims is None:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        agent_id = str(agent_claims.get('agent_id') or '')
        if not agent_id:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        if check_agent_rate_limit(agent_id):
            return JsonResponse({'error': 'rate_limited'}, status=429)
        try:
            company_id_int = _claim_company_id(agent_claims)
        except ValueError:
            return JsonResponse({'error': 'unauthorized'}, status=401)
        if company_id_int is None:
            agent_claims.pop('company_id', None)
        else:
            agent_claims['company_id'] = company_id_int
        if self.identity_revocation_check is None:
            return JsonResponse({'error': 'revocation_unavailable'}, status=403)
        try:
            revoked = bool(self.identity_revocation_check(agent_id, company_id_int))
        except Exception as exc:
            logger.warning(
                'MCP revocation check failed agent_id=%s err=%s',
                agent_id,
                type(exc).__name__,
            )
            return JsonResponse({'error': 'revocation_unavailable'}, status=403)
        if revoked:
            return JsonResponse({'error': 'agent_revoked'}, status=403)
        if not self._service_allowed(agent_claims, self.service_name):
            return JsonResponse({'error': 'forbidden'}, status=403)
        return agent_claims

    def _claims_from_bearer(self, request: HttpRequest) -> dict[str, Any] | None:
        issuer = (self.identity_issuer or '').strip().rstrip('/')
        audience = (self.mcp_audience or '').strip()
        if not issuer or not audience:
            return None
        if self.identity_jwks is None and not (self.identity_jwks_url or '').strip():
            return None
        header = str(request.META.get('HTTP_AUTHORIZATION') or '')
        if not header.lower().startswith('bearer '):
            return None
        token = header[7:].strip()
        if not token:
            return None
        try:
            claims = decode_identity_rs256_jwt(
                token,
                audience=audience,
                issuer=issuer,
                jwks_url=(self.identity_jwks_url or '').strip() or None,
                jwks=self.identity_jwks,
                require_claims=('agent_id',),
            )
        except IdentityJwksError:
            return None
        if not access_token_audience_matches(claims, audience):
            return None
        agent_id = claims.get('agent_id')
        if not isinstance(agent_id, str) or not agent_id.strip():
            return None
        claims['agent_id'] = agent_id.strip()
        return claims

    def _handle_prepared(self, request: HttpRequest, agent_claims: dict[str, Any]) -> JsonResponse:
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'invalid_json'}, status=400)
        method = payload.get('method')
        req_id = payload.get('id')
        params = payload.get('params') or {}
        if method == 'initialize':
            return JsonResponse(self._result(req_id, {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}}}))
        if method == 'tools/list':
            schema = self.schema_provider()
            # Keep ``_meta`` (path/method/read_only): flat agent schemas omit transport
            # fields, and the AI gateway needs registry metadata to route tools/call.
            tools = [_tool_list_row(t) for t in tools_from_schema(schema)]
            return JsonResponse(self._result(req_id, {'tools': tools}))
        if method == 'tools/call':
            return self._tools_call(request, req_id, params, agent_claims)
        return JsonResponse(self._error(req_id, -32601, 'Method not found'))

    def _tools_call(
        self,
        request: HttpRequest,
        req_id: Any,
        params: dict[str, Any],
        agent_claims: dict[str, Any],
    ) -> JsonResponse:
        tool_name = str(params.get('name') or '')
        arguments = params.get('arguments')
        if arguments is None:
            arguments = {}
        try:
            company_id = _claim_company_id(agent_claims)
        except ValueError:
            return JsonResponse(self._error(req_id, -32602, 'company_id does not match the authenticated company'))
        if not tool_arguments_match_company(arguments, company_id):
            return JsonResponse(self._error(req_id, -32602, 'company_id does not match the authenticated company'))
        schema = self.schema_provider()
        tools = tools_from_schema(schema)
        tool = next((t for t in tools if t['name'] == tool_name), None)
        if tool is None:
            return JsonResponse(self._error(req_id, -32602, 'Unknown tool'))
        meta = tool.get('_meta') or {}
        path_template = str(meta.get('path') or '')
        path = str(arguments.get('path') or path_template)
        method = str(arguments.get('method') or meta.get('method') or 'GET').upper()
        if path != path_template or method != meta.get('method'):
            return JsonResponse(self._error(req_id, -32602, 'Tool path mismatch'))
        try:
            validate_mcp_tool_arguments(arguments if isinstance(arguments, dict) else {}, meta)
            path_params = arguments.get('path_params') if isinstance(arguments.get('path_params'), dict) else {}
            resolved_path = materialize_openapi_path(path_template, path_params)
        except McpToolArgumentError as exc:
            return JsonResponse(self._error(req_id, -32602, str(exc)))

        access = str(agent_claims.get('mcp_access') or 'read_only')
        read_level = str(agent_claims.get('mcp_read') or 'safe')
        operation = self._operation(schema, path_template, method)
        destructive = bool(meta.get('destructive')) or is_destructive_operation(operation)
        tool_read_only = bool(meta.get('read_only'))
        request_markers = marker_tree_for_operation_request(operation, schema)
        response_markers = marker_tree_for_operation_response(operation, schema)
        decision = decide_write(
            method=method,
            access_mode=access,
            destructive=destructive,
            allow_destructive_without_asking=bool(agent_claims.get('mcp_destructive')),
            tool_read_only=tool_read_only,
        )
        # Skip a second approval only when the token names this tool and the grant has not expired.
        if decision.needs_approval and _delegated_approval_covers(agent_claims, tool_name):
            decision = WriteGateDecision(allowed=True)
        if decision.needs_approval:
            args_hash = hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()
            approval_payload = {
                'agent_id': agent_claims.get('agent_id'),
                'company_id': agent_claims.get('company_id'),
                'service': self.service_name,
                'action': tool_name,
                'arguments': arguments,
                'arguments_hash': args_hash,
                'path': resolved_path,
                'method': method,
            }
            granted = False
            if self.approval_state:
                state = self.approval_state(approval_payload)
                if state == 'executed':
                    return JsonResponse(
                        self._result(
                            req_id,
                            {'content': [{'type': 'text', 'text': 'Approval already used.'}], 'isError': True},
                        )
                    )
                if state == 'approved':
                    approval_id = approval_payload.get('approval_id')
                    if approval_id and self.approval_consume:
                        consumed = self.approval_consume(str(approval_id), approval_payload)
                        if consumed:
                            granted = True
                    else:
                        return JsonResponse(
                            self._result(
                                req_id,
                                {'content': [{'type': 'text', 'text': 'Approval unavailable.'}], 'isError': True},
                            )
                        )
                elif state == 'pending':
                    return JsonResponse(
                        self._result(
                            req_id,
                            {
                                'content': [{'type': 'text', 'text': 'Approval pending.'}],
                                'isError': True,
                                'meta': {'status': 'pending'},
                            },
                        )
                    )
            if not granted and self.approval_handler:
                pending = self.approval_handler(approval_payload)
                if pending:
                    return JsonResponse(
                        self._result(
                            req_id,
                            {
                                'content': [{'type': 'text', 'text': 'Approval required.'}],
                                'isError': True,
                                'meta': {'approval_id': pending.get('id'), 'status': 'pending'},
                            },
                        )
                    )
            if not granted:
                return JsonResponse(
                    self._result(
                        req_id,
                        {'content': [{'type': 'text', 'text': decision.reason or 'Forbidden'}], 'isError': True},
                    )
                )
        if not decision.allowed:
            return JsonResponse(
                self._result(
                    req_id,
                    {'content': [{'type': 'text', 'text': decision.reason or 'Forbidden'}], 'isError': True},
                )
            )

        inner_kwargs: dict[str, Any] = {
            'query_params': arguments.get('query') or {},
            'HTTP_AUTHORIZATION': request.META.get('HTTP_AUTHORIZATION', ''),
        }
        if method not in _BODYLESS_METHODS:
            body = arguments.get('body')
            inner_kwargs['data'] = body if body is not None else {}
        drf_request = self._factory.generic(method, resolved_path, **inner_kwargs)
        self._attach_request_principal(drf_request, agent_claims)
        from django.urls import resolve

        match = resolve(resolved_path, urlconf=self.urlconf)
        response = match.func(drf_request, *match.args, **match.kwargs)
        status_code = getattr(response, 'status_code', 500)
        try:
            data = response.data  # type: ignore[attr-defined]
        except AttributeError:
            data = {'detail': 'ok'}
        read_sensitive = read_level == 'sensitive'
        redacted = redact_mapping(
            data if isinstance(data, dict) else {'result': data},
            read_sensitive=read_sensitive,
            markers=response_markers,
        )
        if self.on_call:
            self.on_call(
                {
                    'agent_id': agent_claims.get('agent_id'),
                    'company_id': agent_claims.get('company_id'),
                    'service': self.service_name,
                    'tool': tool_name,
                    'method': method,
                    'path': resolved_path,
                    'status': status_code,
                    'arguments': redact_mapping(arguments, read_sensitive=False, markers=request_markers),
                }
            )
        return JsonResponse(
            self._result(
                req_id,
                {
                    'content': [{'type': 'text', 'text': json.dumps(redacted)}],
                    'isError': status_code >= 400,
                },
            )
        )

    @staticmethod
    def _attach_request_principal(target_request, agent_claims: dict[str, Any]) -> None:
        """Authenticate the inner view as the verified token, not the outer request user."""
        agent_id = str(agent_claims.get('agent_id') or '')
        force_authenticate(target_request, user=VerifiedTokenUser(agent_id), token=agent_claims)
        target_request.auth = agent_claims

    @staticmethod
    def _service_allowed(agent_claims: dict[str, Any], service_name: str) -> bool:
        scope = [part for part in str(agent_claims.get('scope') or '').split() if part]
        if not scope:
            return False
        return service_name in scope

    @staticmethod
    def _operation(schema: dict[str, Any], path: str, method: str) -> dict[str, Any] | None:
        item = (schema.get('paths') or {}).get(path) or {}
        return item.get(method.lower())

    @staticmethod
    def _result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {'jsonrpc': '2.0', 'id': req_id, 'result': result}

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': code, 'message': message}}
