from django.test import SimpleTestCase

from shellui_django.mcp.resources import (
    access_token_audience_matches,
    is_valid_mcp_service_url,
    mcp_resource_from_origin,
    normalize_resource_indicator,
)


class McpResourceTests(SimpleTestCase):
    def test_canonical_resource(self):
        self.assertEqual(mcp_resource_from_origin('https://auth.example.com'), 'https://auth.example.com/mcp')

    def test_normalize_resource(self):
        self.assertEqual(
            normalize_resource_indicator('https://auth.example.com/mcp'),
            'https://auth.example.com/mcp',
        )
        self.assertIsNone(normalize_resource_indicator('https://auth.example.com/other'))

    def test_audience_match(self):
        payload = {'aud': 'https://auth.example.com/mcp'}
        self.assertTrue(access_token_audience_matches(payload, 'https://auth.example.com/mcp'))
        self.assertFalse(access_token_audience_matches(payload, 'https://storage.example.com/mcp'))

    def test_is_valid_mcp_service_url(self):
        self.assertTrue(is_valid_mcp_service_url('https://auth.example.com/mcp'))
        self.assertFalse(is_valid_mcp_service_url('https://foreign.example.com/other'))
        self.assertFalse(is_valid_mcp_service_url(''))
