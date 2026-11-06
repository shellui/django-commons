"""Aggregated MCP gateway: tenant isolation, forwarding, and tool catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import patch

import jwt
from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, override_settings

from shellui_django.mcp.gateway import AggregatingMcpServer, McpGatewayConfig, public_mcp_tools

IDENTITY_MCP = 'https://identity.test/mcp'
STORAGE_MCP = 'https://storage.test/mcp'

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
        self.server = AggregatingMcpServer(
            gateway=self.gateway_config,
            schema_provider=lambda: LOCAL_SCHEMA,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name='identity',
        )

    def _post(self, body: str, *, claims: dict | None = None):
        request = self.factory.post('/mcp', data=body, content_type='application/json')
        request.user = None
        request.auth = claims
        return self.server.handle(request, agent_claims=claims)

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
    def test_invalid_downstream_mcp_url_skips_remote_tools(self, post):
        bad_url_config = McpGatewayConfig(
            get_service_urls=lambda: {'identity': IDENTITY_MCP, 'storage': 'https://foreign.example.com/other'},
            resolve_agent=self.gateway_config.resolve_agent,
            mint_downstream_token=self.gateway_config.mint_downstream_token,
            local_service_id='identity',
        )
        server = AggregatingMcpServer(
            gateway=bad_url_config,
            schema_provider=lambda: LOCAL_SCHEMA,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name='identity',
        )
        response = server.handle(
            self.factory.post('/mcp', data=_rpc('tools/list'), content_type='application/json'),
            agent_claims=self.claims_a,
        )
        self.assertEqual(response.status_code, 200)
        post.assert_not_called()
        names = {t['name'] for t in json.loads(response.content)['result']['tools']}
        self.assertIn('api_v1_mcp_services_list', names)

    @patch('shellui_django.mcp.gateway.requests.post')
    def test_tools_call_invalid_downstream_url_fails_closed(self, post):
        bad_url_config = McpGatewayConfig(
            get_service_urls=lambda: {'identity': IDENTITY_MCP, 'storage': 'https://evil.test/nope'},
            resolve_agent=self.gateway_config.resolve_agent,
            mint_downstream_token=self.gateway_config.mint_downstream_token,
            local_service_id='identity',
        )
        server = AggregatingMcpServer(
            gateway=bad_url_config,
            schema_provider=lambda: LOCAL_SCHEMA,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name='identity',
        )
        cache.set(
            'mcp_gateway:route:storage_v1_run',
            {'service_id': 'storage', 'downstream_name': 'storage_v1_run'},
            60,
        )
        response = server.handle(
            self.factory.post(
                '/mcp',
                data=_rpc('tools/call', name='storage_v1_run', arguments={}),
                content_type='application/json',
            ),
            agent_claims=self.claims_a,
        )
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertTrue(body['result']['isError'])
        self.assertIn('unavailable', body['result']['content'][0]['text'].lower())
        post.assert_not_called()

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
        server = AggregatingMcpServer(
            gateway=self.gateway_config,
            schema_provider=lambda: EMPTY_SCHEMA,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name='identity',
        )
        with patch(
            'shellui_django.mcp.gateway.tools_from_schema',
            return_value=[{'name': 'shared_tool', 'description': 'local'}],
        ):
            request = self.factory.post('/mcp', data=_rpc('tools/list'), content_type='application/json')
            response = server.handle(request, agent_claims=self.claims_a)
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
        server = AggregatingMcpServer(
            gateway=self.gateway_config,
            schema_provider=lambda: EMPTY_SCHEMA,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name='identity',
        )
        with patch('shellui_django.mcp.gateway.tools_from_schema', return_value=[]):
            list_resp = server.handle(
                self.factory.post('/mcp', data=_rpc('tools/list'), content_type='application/json'),
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
            self.factory.post(
                '/mcp',
                data=_rpc('tools/call', name='storage_v1_x', arguments={}),
                content_type='application/json',
            ),
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
            self.factory.post(
                '/mcp',
                data=_rpc('tools/call', name='storage_v1_run', arguments={'body': {'company_id': 10}}),
                content_type='application/json',
            ),
            agent_claims=self.claims_b,
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

    @patch('shellui_django.mcp.gateway.requests.post', side_effect=ConnectionError('down'))
    def test_no_token_in_logs(self, _post):
        config = McpGatewayConfig(
            get_service_urls=lambda: {'identity': IDENTITY_MCP, 'storage': STORAGE_MCP},
            resolve_agent=lambda c: self._agents.get((str(c['agent_id']), int(c['company_id']))),
            mint_downstream_token=lambda _agent, _resource: 'mcp-test-token-leak-check',
            local_service_id='identity',
        )
        server = AggregatingMcpServer(
            gateway=config,
            schema_provider=lambda: LOCAL_SCHEMA,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name='identity',
        )
        with self.assertLogs('shellui_django.mcp.gateway', level='WARNING') as logs:
            server.handle(
                self.factory.post('/mcp', data=_rpc('tools/list'), content_type='application/json'),
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
    def test_public_mcp_tools_strips_private_keys(self):
        raw = [{'name': 'a', '_meta': {'x': 1}}]
        self.assertEqual(public_mcp_tools(raw), [{'name': 'a'}])
