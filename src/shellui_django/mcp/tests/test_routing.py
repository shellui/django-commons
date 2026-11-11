from django.test import SimpleTestCase

from shellui_django.mcp.routing import McpToolArgumentError, materialize_openapi_path, validate_mcp_tool_arguments


class MaterializeOpenApiPathTests(SimpleTestCase):
    def test_substitutes_and_encodes(self):
        path = materialize_openapi_path(
            '/api/v1/companies/{company_id}/items/{item_id}/',
            {'company_id': '42', 'item_id': 'acme widget'},
        )
        self.assertEqual(path, '/api/v1/companies/42/items/acme%20widget/')

    def test_rejects_path_injection(self):
        with self.assertRaises(McpToolArgumentError):
            materialize_openapi_path('/api/{company_id}/', {'company_id': '../other'})

    def test_rejects_missing_and_extra_params(self):
        with self.assertRaises(McpToolArgumentError):
            materialize_openapi_path('/api/{company_id}/', {})
        with self.assertRaises(McpToolArgumentError):
            materialize_openapi_path('/api/{company_id}/', {'company_id': '1', 'extra': 'x'})


class ValidateMcpToolArgumentsTests(SimpleTestCase):
    def test_strict_query_and_body(self):
        meta = {
            'path': '/api/{company_id}/',
            'query_fields': ['limit'],
            'body_fields': ['name'],
        }
        validate_mcp_tool_arguments(
            {
                'path_params': {'company_id': '9'},
                'query': {'limit': '10'},
                'body': {'name': 'Ada'},
            },
            meta,
        )
        with self.assertRaises(McpToolArgumentError):
            validate_mcp_tool_arguments(
                {'path_params': {'company_id': '9'}, 'query': {'limit': '1', 'evil': '1'}},
                meta,
            )

    def test_ignores_drf_format_query_field(self):
        meta = {
            'path': '/api/v1/users',
            'query_fields': ['page', 'page_size', 'q'],
        }
        arguments = {
            'path_params': {},
            'query': {'format': 'json', 'page': 1, 'page_size': 100},
        }
        validate_mcp_tool_arguments(arguments, meta)
        self.assertNotIn('format', arguments['query'])
        self.assertEqual(arguments['query']['page'], 1)
