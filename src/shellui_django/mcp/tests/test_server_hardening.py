"""MCP handler: verified bearer token, tenant binding, revocation, delegated approval."""

from __future__ import annotations

import json
import time

from django.test import RequestFactory, SimpleTestCase, override_settings

from shellui_django.mcp.server import McpServer
from shellui_django.mcp.tests.rs256_helpers import generate_test_rsa_jwks, sign_test_agent_access_token

ISSUER = 'https://identity.example.com'
AUDIENCE = 'https://saas.example.com/mcp'

SCHEMA = {
    'paths': {
        '/api/v1/companies/{company_id}/items/': {
            'get': {
                'tags': ['mcp-tools'],
                'operationId': 'list_company_items',
            },
        },
        '/api/v1/templates/render-preview/': {
            'post': {
                'tags': ['mcp-tools'],
                'operationId': 'create_note',
            },
        },
    },
}


class _OuterUser:
    is_authenticated = True
    marker = 'outer-user'
    agent_id = 'outer-user'


@override_settings(ROOT_URLCONF='shellui_django.mcp.tests.mcp_routing_urlconf')
class McpServerHardeningTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()

    def setUp(self):
        self.factory = RequestFactory()
        self.revoked = False
        self.revocation_calls: list[tuple[str, int | None]] = []
        self.approvals: list[dict] = []
        self.claims = {
            'agent_id': '00000000-0000-0000-0000-000000000099',
            'company_id': 42,
            'scope': 'saas',
            'mcp_access': 'full',
            'mcp_read': 'safe',
        }
        self.server = self._server()

    def _revocation(self, agent_id: str, company_id: int | None) -> bool:
        self.revocation_calls.append((agent_id, company_id))
        if self.revoked == 'raise':
            raise RuntimeError('revocation backend down')
        return bool(self.revoked)

    def _server(self, **kwargs):
        params = {
            'schema_provider': lambda: SCHEMA,
            'urlconf': 'shellui_django.mcp.tests.mcp_routing_urlconf',
            'service_name': 'saas',
            'identity_revocation_check': self._revocation,
            'identity_issuer': ISSUER,
            'identity_jwks': self.jwks,
            'mcp_audience': AUDIENCE,
            'approval_handler': self._approval,
        }
        params.update(kwargs)
        return McpServer(**params)

    def _approval(self, payload):
        self.approvals.append(payload)
        return {'id': 'approval-1'}

    def _token(self, claims):
        return sign_test_agent_access_token(
            claims,
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=ISSUER,
            audience=AUDIENCE,
        )

    def _post(self, method, params, *, claims=None, authorization='signed', server=None, passed_claims=None):
        claims = self.claims if claims is None else claims
        if authorization == 'signed':
            header = f'Bearer {self._token(claims)}'
        else:
            header = authorization
        request = self.factory.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
            content_type='application/json',
            HTTP_AUTHORIZATION=header,
        )
        request.user = _OuterUser()
        request.auth = {'agent_id': 'intruder', 'company_id': 7, 'scope': 'saas', 'mcp_access': 'full'}
        return (server or self.server).handle(request, agent_claims=passed_claims)

    def _call(self, arguments, **kwargs):
        return self._post('tools/call', {'name': 'list_company_items', 'arguments': arguments}, **kwargs)

    def test_claims_dict_without_bearer_is_unauthorized(self):
        response = self._post(
            'tools/list',
            {},
            authorization='',
            passed_claims=self.claims,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)['error'], 'unauthorized')

    def test_inner_view_uses_verified_token_not_outer_principal(self):
        response = self._call(
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '42'},
            },
            passed_claims={'agent_id': 'intruder', 'company_id': 7, 'scope': 'saas', 'mcp_access': 'full'},
        )
        self.assertEqual(response.status_code, 200)
        body = json.loads(json.loads(response.content)['result']['content'][0]['text'])
        self.assertEqual(body['company_id'], 42)
        self.assertEqual(body['agent_id'], self.claims['agent_id'])
        self.assertEqual(body['user_agent_id'], self.claims['agent_id'])
        self.assertIsNone(body['user_marker'])

    def test_other_company_in_path_query_and_body_is_rejected(self):
        cases = [
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '7'},
            },
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '42'},
                'query': {'company_id': 7},
            },
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '42'},
                'query': {'companyId': '7'},
            },
        ]
        for arguments in cases:
            response = self._call(arguments)
            payload = json.loads(response.content)
            self.assertIn('error', payload, arguments)
            self.assertIn('company_id', payload['error']['message'])
        response = self._post(
            'tools/call',
            {
                'name': 'create_note',
                'arguments': {
                    'path': '/api/v1/templates/render-preview/',
                    'method': 'POST',
                    'body': {'owner': {'company_id': 7}},
                },
            },
        )
        payload = json.loads(response.content)
        self.assertIn('company_id', payload['error']['message'])

    def test_matching_company_id_is_allowed(self):
        response = self._call(
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '42'},
                'query': {'company_id': 42},
            }
        )
        payload = json.loads(response.content)
        self.assertFalse(payload['result'].get('isError'))
        body = json.loads(payload['result']['content'][0]['text'])
        self.assertEqual(body['company_id'], 42)

    def test_missing_revocation_hook_fails_closed(self):
        server = self._server(identity_revocation_check=None)
        response = self._post('tools/list', {}, server=server)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)['error'], 'revocation_unavailable')

    def test_revocation_hook_error_fails_closed(self):
        self.revoked = 'raise'
        response = self._post('tools/list', {})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)['error'], 'revocation_unavailable')

    def test_revoked_agent_is_rejected(self):
        self.revoked = True
        response = self._post('tools/list', {})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)['error'], 'agent_revoked')
        self.assertEqual(self.revocation_calls, [(self.claims['agent_id'], 42)])

    def _write_call(self, claims):
        return self._post(
            'tools/call',
            {
                'name': 'create_note',
                'arguments': {
                    'path': '/api/v1/templates/render-preview/',
                    'method': 'POST',
                    'body': {},
                },
            },
            claims=claims,
        )

    def test_boolean_gateway_delegated_does_not_skip_approval(self):
        claims = dict(self.claims)
        claims['mcp_access'] = 'ask'
        claims['mcp_gateway_delegated'] = True
        response = self._write_call(claims)
        self.assertEqual(len(self.approvals), 1)
        payload = json.loads(response.content)
        self.assertEqual(payload['result']['meta']['status'], 'pending')

    def test_delegated_grant_for_another_action_does_not_skip_approval(self):
        claims = dict(self.claims)
        claims['mcp_access'] = 'ask'
        claims['mcp_gateway_delegated'] = {'action': 'other_tool', 'exp': int(time.time()) + 120}
        response = self._write_call(claims)
        self.assertEqual(len(self.approvals), 1)
        self.assertEqual(json.loads(response.content)['result']['meta']['status'], 'pending')

    def test_expired_delegated_grant_does_not_skip_approval(self):
        claims = dict(self.claims)
        claims['mcp_access'] = 'ask'
        claims['mcp_gateway_delegated'] = {'action': 'create_note', 'exp': int(time.time()) - 30}
        response = self._write_call(claims)
        self.assertEqual(len(self.approvals), 1)
        self.assertEqual(json.loads(response.content)['result']['meta']['status'], 'pending')

    def test_delegated_grant_for_this_action_skips_second_approval(self):
        claims = dict(self.claims)
        claims['mcp_access'] = 'ask'
        claims['mcp_gateway_delegated'] = {'action': 'create_note', 'exp': int(time.time()) + 120}
        response = self._write_call(claims)
        self.assertEqual(self.approvals, [])
        payload = json.loads(response.content)
        self.assertFalse(payload['result'].get('isError'))
