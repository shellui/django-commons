import json
import unittest

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
                'operationId': 'render_preview',
                'x-mcp': {'read_only': True},
            },
        },
    },
}


class _AuthUser:
    is_authenticated = True
    marker = 'outer-user'


@override_settings(ROOT_URLCONF='shellui_django.mcp.tests.mcp_routing_urlconf')
class McpServerRoutingTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()

    def setUp(self):
        self.factory = RequestFactory()
        self.seen_revocation: list[tuple[str, int | None]] = []

        def _revocation_check(agent_id: str, company_id: int | None) -> bool:
            self.seen_revocation.append((agent_id, company_id))
            return False

        self.server = McpServer(
            schema_provider=lambda: SCHEMA,
            urlconf='shellui_django.mcp.tests.mcp_routing_urlconf',
            service_name='saas',
            identity_revocation_check=_revocation_check,
            identity_issuer=ISSUER,
            identity_jwks=self.jwks,
            mcp_audience=AUDIENCE,
        )
        self.claims = {
            'agent_id': '00000000-0000-0000-0000-000000000099',
            'company_id': 42,
            'scope': 'saas',
            'mcp_access': 'full',
            'mcp_read': 'safe',
        }

    def _token(self, claims):
        return sign_test_agent_access_token(
            claims,
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=ISSUER,
            audience=AUDIENCE,
        )

    def _call_tool(self, arguments, *, claims=None):
        claims = claims or self.claims
        request = self.factory.post(
            '/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'tools/call',
                    'params': {'name': 'list_company_items', 'arguments': arguments},
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._token(claims)}',
        )
        request.user = _AuthUser()
        request.auth = {'agent_id': 'other-agent', 'company_id': 7}
        return self.server.handle(request, agent_claims={'agent_id': 'other-agent', 'company_id': 7, 'scope': 'saas'})

    def test_passes_agent_and_company_to_revocation_check(self):
        self._call_tool(
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '7'},
            }
        )
        self.assertEqual(self.seen_revocation, [(self.claims['agent_id'], 42)])

    def test_get_tool_does_not_send_empty_json_body(self):
        """Bodyless HTTP methods must not attach a JSON body (avoids DRF 415)."""
        response = self._call_tool(
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '42'},
            }
        )
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertFalse(payload['result'].get('isError'))

    def test_resolves_path_template_and_propagates_principal(self):
        response = self._call_tool(
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '42'},
            }
        )
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        result = payload['result']
        self.assertFalse(result.get('isError'))
        body = json.loads(result['content'][0]['text'])
        self.assertEqual(body['company_id'], 42)
        self.assertEqual(body['agent_id'], self.claims['agent_id'])
        self.assertTrue(body['user_ok'])
        self.assertEqual(body['user_agent_id'], self.claims['agent_id'])
        self.assertIsNone(body['user_marker'])

    def test_read_only_post_tool_allowed_in_read_only_mode(self):
        claims = dict(self.claims)
        claims['mcp_access'] = 'read_only'
        request = self.factory.post(
            '/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 2,
                    'method': 'tools/call',
                    'params': {
                        'name': 'render_preview',
                        'arguments': {
                            'path': '/api/v1/templates/render-preview/',
                            'method': 'POST',
                            'body': {},
                        },
                    },
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self._token(claims)}',
        )
        request.user = _AuthUser()
        request.auth = claims
        response = self.server.handle(request, agent_claims=claims)
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertFalse(payload['result'].get('isError'))

    def test_rejects_unsafe_path_param(self):
        response = self._call_tool(
            {
                'path': '/api/v1/companies/{company_id}/items/',
                'method': 'GET',
                'path_params': {'company_id': '1/2'},
            }
        )
        payload = json.loads(response.content)
        self.assertIn('error', payload)


if __name__ == '__main__':
    unittest.main()
