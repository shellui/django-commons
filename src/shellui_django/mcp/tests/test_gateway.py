"""Aggregated MCP gateway: tenant isolation, forwarding, and tool catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import patch

import jwt
from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, override_settings

from shellui_django.mcp.gateway import AggregatingMcpServer, McpGatewayConfig, public_mcp_tools
from shellui_django.mcp.tests.rs256_helpers import generate_test_rsa_jwks, sign_test_agent_access_token

IDENTITY_MCP = 'https://identity.test/mcp'
STORAGE_MCP = 'https://storage.test/mcp'
ISSUER = 'https://identity.example.com'
AUDIENCE = 'https://gateway.example.com/mcp'

LOCAL_SCHEMA = {
    'paths': {
        '/api/v1/mcp/services/': {
            'get': {
                'tags': ['mcp-tools'],
                'operationId': 'api_v1_mcp_services_list',
            },
        },
    },
}

EMPTY_SCHEMA: dict = {'paths': {}}


@dataclass
class StubAgent:
    id: str
    company_id: int
    services_allowed: list[str]


def _rpc(method: str, **params):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}
    return json.dumps(body)


def _mint(agent: StubAgent, resource: str) -> str:
    return jwt.encode(
        {
            'agent_id': agent.id,
            'company_id': agent.company_id,
            'aud': resource,
            'scope': ' '.join(agent.services_allowed),
        },
        'test-secret',
        algorithm='HS256',
    )


def _resolve(claims: dict) -> StubAgent | None:
    agent_id = claims.get('agent_id')
    company_id = claims.get('company_id')
    if not agent_id or company_id is None:
        return None
    scope = [p for p in str(claims.get('scope') or '').split() if p]
    return StubAgent(id=str(agent_id), company_id=int(company_id), services_allowed=scope)


@override_settings(
    AUTH_RATE_LIMIT_ENABLED=False,
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'mcp-gateway-tests',
        }
    },
)
class McpGatewayTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()

    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.agent_a = StubAgent(
            id='agent-a',
            company_id=10,
            services_allowed=['identity', 'storage'],
        )
        self.agent_b = StubAgent(
            id='agent-b',
            company_id=20,
            services_allowed=['identity', 'storage'],
        )
        self.claims_a = {
            'agent_id': self.agent_a.id,
            'company_id': self.agent_a.company_id,
            'scope': 'identity storage',
            'mcp_access': 'full',
        }
        self.claims_b = {
            'agent_id': self.agent_b.id,
            'company_id': self.agent_b.company_id,
            'scope': 'identity storage',
            'mcp_access': 'full',
        }
        self._agents = {
            (self.agent_a.id, self.agent_a.company_id): self.agent_a,
            (self.agent_b.id, self.agent_b.company_id): self.agent_b,
        }

        def resolve(claims: dict) -> StubAgent | None:
            key = (str(claims.get('agent_id')), int(claims.get('company_id')))
            return self._agents.get(key)

        self.gateway_config = McpGatewayConfig(
            get_service_urls=lambda: {'identity': IDENTITY_MCP, 'storage': STORAGE_MCP},
            resolve_agent=resolve,
            mint_downstream_token=_mint,
            local_service_id='identity',
            instructions_title='Shellui Identity MCP gateway.',
        )
        self.server = self._make_server(LOCAL_SCHEMA)

    def _make_server(self, schema, *, gateway=None, service_name='identity'):
        return AggregatingMcpServer(
            gateway=gateway or self.gateway_config,
            schema_provider=lambda schema=schema: schema,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name=service_name,
            identity_revocation_check=lambda _agent_id, _company_id: False,
            identity_issuer=ISSUER,
            identity_jwks=self.jwks,
            mcp_audience=AUDIENCE,
        )

    def _request(self, body: str, *, claims: dict | None = None):
        claims = self.claims_a if claims is None else claims
        token = sign_test_agent_access_token(
            claims,
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=ISSUER,
            audience=AUDIENCE,
        )
        request = self.factory.post(
            '/mcp',
            data=body,
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        request.user = None
        request.auth = {'agent_id': 'not-the-token', 'company_id': 1}
        return request

    def _post(self, body: str, *, claims: dict | None = None):
        return self.server.handle(self._request(body, claims=claims), agent_claims=None)

    @patch('shellui_django.mcp.gateway.requests.post')
    def test_tools_list_includes_remote_when_downstream_ok(self, post):
        storage_tools = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'tools': [{'name': 'storage_v1_list_buckets', 'description': 'List buckets'}]},
        }

        def side_effect(url, **kwargs):
            from unittest.mock import Mock

            resp = Mock()
            resp.status_code = 200
            resp.json.return_value = storage_tools
            return resp

        post.side_effect = side_effect
        response = self._post(_rpc('tools/list'), claims=self.claims_a)
        self.assertEqual(response.status_code, 200)
        names = {t['name'] for t in json.loads(response.content)['result']['tools']}
        self.assertIn('storage_v1_list_buckets', names)
        self.assertIn('api_v1_mcp_services_list', names)

    @patch('shellui_django.mcp.gateway.requests.post')
    def test_downstream_failure_omits_remote_tools(self, post):
        post.side_effect = ConnectionError('refused')
        response = self._post(_rpc('tools/list'), claims=self.claims_a)
        self.assertEqual(response.status_code, 200)
        names = {t['name'] for t in json.loads(response.content)['result']['tools']}
        self.assertNotIn('storage_v1_list_buckets', names)
        self.assertIn('api_v1_mcp_services_list', names)

    @patch('shellui_django.mcp.gateway.requests.post')
    def test_collision_adds_service_namespace(self, post):
        dup_tool = {'name': 'shared_tool', 'description': 'dup'}

        def side_effect(url, **kwargs):
            from unittest.mock import Mock

            resp = Mock()
            resp.status_code = 200
            resp.json.return_value = {'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [dup_tool]}}
            return resp

        post.side_effect = side_effect
        server = self._make_server(EMPTY_SCHEMA)
        with patch(
            'shellui_django.mcp.gateway.tools_from_schema',
            return_value=[{'name': 'shared_tool', 'description': 'local'}],
        ):
            response = server.handle(self._request(_rpc('tools/list')), agent_claims=self.claims_a)
        names = [t['name'] for t in json.loads(response.content)['result']['tools']]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('storage__shared_tool', names)

    @patch('shellui_django.mcp.gateway.requests.post')
    def test_services_allowed_blocks_forward(self, post):
        claims = {
            'agent_id': self.agent_a.id,
            'company_id': self.agent_a.company_id,
            'scope': 'identity',
            'mcp_access': 'full',
        }
        self.agent_a.services_allowed = ['identity']
        server = self._make_server(EMPTY_SCHEMA)
        with patch('shellui_django.mcp.gateway.tools_from_schema', return_value=[]):
            list_resp = server.handle(
                self._request(_rpc('tools/list'), claims=claims),
                agent_claims=claims,
            )
        self.assertEqual(list_resp.status_code, 200)
        post.assert_not_called()
        cache.set(
            'mcp_gateway:route:storage_v1_x',
            {'service_id': 'storage', 'downstream_name': 'storage_v1_x'},
            60,
        )
        call_resp = server.handle(
            self._request(_rpc('tools/call', name='storage_v1_x', arguments={}), claims=claims),
            agent_claims=claims,
        )
        self.assertEqual(call_resp.status_code, 200)
        self.assertIn('Forbidden', json.loads(call_resp.content)['error']['message'])
        post.assert_not_called()

    @patch('shellui_django.mcp.gateway.requests.post')
    def test_tenant_isolation_on_forwarded_call(self, post):
        from unittest.mock import Mock

        downstream = {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'content': [{'type': 'text', 'text': 'ok'}], 'isError': False},
        }
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = downstream
        post.return_value = resp

        cache.set(
            'mcp_gateway:route:storage_v1_run',
            {'service_id': 'storage', 'downstream_name': 'storage_v1_run'},
            60,
        )
        response = self.server.handle(
            self._request(
                _rpc('tools/call', name='storage_v1_run', arguments={'body': {'company_id': 20}}),
                claims=self.claims_b,
            ),
            agent_claims={'agent_id': self.agent_a.id, 'company_id': 10, 'scope': 'identity storage'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content)['result']['content'][0]['text'], 'ok')
        self.assertEqual(post.call_count, 1)
        _args, kwargs = post.call_args
        self.assertEqual(_args[0], STORAGE_MCP)
        auth_header = kwargs['headers']['Authorization']
        self.assertTrue(auth_header.startswith('Bearer '))
        downstream_token = auth_header.split(' ', 1)[1]
        payload = jwt.decode(downstream_token, options={'verify_signature': False})
        self.assertEqual(payload['company_id'], self.agent_b.company_id)
        self.assertEqual(payload['agent_id'], self.agent_b.id)
        self.assertEqual(payload['aud'], STORAGE_MCP)

    @patch('shellui_django.mcp.gateway.requests.post')
    def test_forward_rejects_other_company_in_arguments(self, post):
        cache.set(
            'mcp_gateway:route:storage_v1_run',
            {'service_id': 'storage', 'downstream_name': 'storage_v1_run'},
            60,
        )
        response = self.server.handle(
            self._request(
                _rpc('tools/call', name='storage_v1_run', arguments={'body': {'company_id': 10}}),
                claims=self.claims_b,
            ),
            agent_claims=self.claims_a,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('company_id', json.loads(response.content)['error']['message'])
        post.assert_not_called()

    @patch('shellui_django.mcp.gateway.requests.post', side_effect=ConnectionError('down'))
    def test_no_token_in_logs(self, _post):
        config = McpGatewayConfig(
            get_service_urls=lambda: {'identity': IDENTITY_MCP, 'storage': STORAGE_MCP},
            resolve_agent=lambda c: self._agents.get((str(c['agent_id']), int(c['company_id']))),
            mint_downstream_token=lambda _agent, _resource: 'mcp-test-token-leak-check',
            local_service_id='identity',
        )
        server = self._make_server(LOCAL_SCHEMA, gateway=config)
        with self.assertLogs('shellui_django.mcp.gateway', level='WARNING') as logs:
            server.handle(
                self._request(_rpc('tools/list')),
                agent_claims=self.claims_a,
            )
        joined = '\n'.join(logs.output)
        self.assertNotIn('mcp-test-token-leak-check', joined)
        self.assertNotIn('Bearer ', joined)

    def test_initialize_lists_connected_services(self):
        response = self._post(_rpc('initialize'), claims=self.claims_a)
        instructions = json.loads(response.content)['result']['instructions']
        self.assertIn('identity', instructions)
        self.assertIn('storage', instructions)


class GatewayHelperTests(SimpleTestCase):
    def test_public_mcp_tools_keeps_meta_strips_other_private_keys(self):
        raw = [{'name': 'a', '_meta': {'path': '/x', 'method': 'GET'}, '_private': 1}]
        self.assertEqual(
            public_mcp_tools(raw),
            [{'name': 'a', '_meta': {'path': '/x', 'method': 'GET'}}],
        )
