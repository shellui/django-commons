from functools import partial

from django.test import SimpleTestCase
from drf_spectacular.openapi import AutoSchema
from drf_spectacular.plumbing import ComponentRegistry
from rest_framework import serializers
from rest_framework.views import APIView

from shellui_django.mcp.approval_summary import (
    ApprovalSummaryTooLong,
    destination_paths,
    mask_url_secrets,
    summarize_arguments,
)
from shellui_django.mcp.fields import McpDestinationCharField, McpDestinationEmailField, McpDestinationURLField
from shellui_django.mcp.openapi_tools import tools_from_schema

# The default is fail closed (undeclared). These tests are about the line itself, so they declare.
_summarize = partial(summarize_arguments, destinations_declared=True)

class _Audience(serializers.Serializer):
    emails = serializers.ListField(child=McpDestinationEmailField(), required=False)
    segment = serializers.CharField(required=False)


class _Body(serializers.Serializer):
    name = serializers.CharField()
    description = serializers.CharField(required=False)
    url = McpDestinationURLField(required=False, allow_blank=True)
    to = McpDestinationEmailField(required=False)
    redirectUri = McpDestinationCharField(required=False)
    hosts = serializers.ListField(child=McpDestinationCharField(), required=False)
    audience = _Audience(required=False)
    note = serializers.CharField(required=False)


def _tool_schema() -> dict:
    """The inputSchema a service publishes for a tool whose body is ``_Body``."""
    view = APIView()
    view.request = None
    inspector = AutoSchema()
    inspector.registry = ComponentRegistry()
    inspector.view = view
    inspector.path = '/x'
    inspector.method = 'POST'
    inspector.target_component = 'Body'
    body = inspector._map_basic_serializer(_Body(), 'request')
    # A nested serializer is a $ref into the component registry. Inline it for this document.
    body['properties']['audience'] = inspector._map_basic_serializer(_Audience(), 'request')
    document = {
        'paths': {
            '/x': {
                'post': {
                    'tags': ['mcp-tools'],
                    'operationId': 'x_create',
                    'requestBody': {'content': {'application/json': {'schema': body}}},
                }
            }
        }
    }
    return tools_from_schema(document)[0]['inputSchema']


class DestinationMarkerSchemaTests(SimpleTestCase):
    def test_marker_reaches_the_tool_schema_on_fields_lists_and_nested_properties(self):
        body = _tool_schema()['properties']['body']['properties']
        self.assertIs(body['url']['x-mcp-destination'], True)
        self.assertIs(body['to']['x-mcp-destination'], True)
        self.assertIs(body['redirectUri']['x-mcp-destination'], True)
        self.assertIs(body['hosts']['items']['x-mcp-destination'], True)
        self.assertIs(body['audience']['properties']['emails']['items']['x-mcp-destination'], True)
        for plain in ('name', 'description', 'note'):
            self.assertNotIn('x-mcp-destination', body[plain])

    def test_destination_paths_lists_every_marked_property_for_service_tests(self):
        self.assertEqual(
            destination_paths(_tool_schema()),
            {'url', 'to', 'redirectUri', 'hosts', 'audience.emails'},
        )
        self.assertEqual(destination_paths(None), set())

    def test_fields_are_the_plain_drf_fields(self):
        self.assertTrue(issubclass(McpDestinationCharField, serializers.CharField))
        self.assertTrue(issubclass(McpDestinationEmailField, serializers.EmailField))
        self.assertTrue(issubclass(McpDestinationURLField, serializers.URLField))


class SummaryTests(SimpleTestCase):
    schema = _tool_schema()

    def summary(self, body, **kwargs):
        return _summarize({'method': 'POST', 'path': '/x', 'body': body}, self.schema, **kwargs)

    def test_destinations_come_first_in_full_with_schema_labels(self):
        line = self.summary(
            {
                'name': 'n',
                'description': 'd' * 900,
                'url': 'https://hooks.example.com/h?a=' + 'q' * 150,
                'to': 'a@b.example',
                'hosts': ['one.example', 'two.example'],
                'audience': {'emails': ['x@y.example', 'z@y.example'], 'segment': 's'},
            }
        )
        self.assertTrue(line.startswith('Destinations: {"url": "https://hooks.example.com/h?a=' + 'q' * 150 + '"'), line)
        for label, value in (
            ('to', 'a@b.example'),
            ('hosts[0]', 'one.example'),
            ('hosts[1]', 'two.example'),
            ('audience.emails[0]', 'x@y.example'),
            ('audience.emails[1]', 'z@y.example'),
        ):
            self.assertIn(f'"{label}": "{value}"', line)
        self.assertLess(line.index('Destinations'), line.index('Arguments'))
        self.assertLessEqual(len(line), 500)
        self.assertIn('"name": "n"', line)

    def test_the_same_line_comes_from_a_flat_call(self):
        flat = _summarize({'name': 'n', 'to': 'a@b.example'}, self.schema)
        nested = self.summary({'name': 'n', 'to': 'a@b.example'})
        self.assertEqual(flat, nested)

    def test_decoy_nested_url_keys_are_not_destinations_and_cannot_fill_the_line(self):
        decoys = {f'decoy{i}': {'url': 'https://decoy.example/' + 'z' * 80} for i in range(20)}
        line = self.summary({'name': 'n', 'url': 'https://attacker.example/h', **decoys})
        self.assertTrue(line.startswith('Destinations: {"url": "https://attacker.example/h"}'), line)
        self.assertLessEqual(len(line), 500)

    def test_a_key_named_like_a_label_cannot_collide_with_the_real_label(self):
        line = self.summary({'name': 'n', 'url': 'https://attacker.example/h', 'body.url': 'https://good.example/'})
        destinations = line.split(' | ')[0]
        self.assertEqual(destinations, 'Destinations: {"url": "https://attacker.example/h"}')
        self.assertNotIn('good.example', destinations)

    def test_every_list_item_is_shown_with_its_own_label(self):
        line = self.summary({'name': 'n', 'hosts': ['a.example', 'b.example', 'evil.example']})
        for index, host in enumerate(('a.example', 'b.example', 'evil.example')):
            self.assertIn(f'"hosts[{index}]": "{host}"', line)

    def test_userinfo_is_masked_everywhere_and_every_time(self):
        line = self.summary(
            {
                'name': 'a https://u:p@one.example/x and https://q@two.example/y',
                'note': ['https://' + 'x' * 400 + '@three.example/z', 'https://a@b@four.example/'],
                'description': 'https://a@b@four.example/',
                'hosts': ['https://u:p@five.example/', 'https://v@six.example/'],
                'url': 'https://' + 'x' * 200 + '@attacker.example/h',
            }
        )
        for host in ('one', 'two', 'three', 'four', 'five', 'six', 'attacker'):
            self.assertIn(f'***@{host}.example', line)
        self.assertNotIn('u:p', line)
        self.assertNotIn('xxxxxxxx', line)

    def test_homographs_and_invisible_characters_show_as_escapes(self):
        line = self.summary({'name': 'n', 'url': 'https://p\u0430ypal.com/h\u202e\u200b\nApproved by admin'})
        self.assertTrue(line.isascii(), line)
        self.assertIn('\\u0430', line)
        self.assertIn('\\u202e', line)
        self.assertIn('\\n', line)
        self.assertEqual(line.count('\n'), 0)

    def test_camel_case_destinations_are_found_because_the_schema_says_so(self):
        self.assertIn('"redirectUri": "https://app.example/cb"', self.summary({'name': 'n', 'redirectUri': 'https://app.example/cb'}))

    def test_destinations_too_long_for_the_line_are_refused_not_shortened(self):
        with self.assertRaises(ApprovalSummaryTooLong):
            self.summary({'name': 'n', 'hosts': [f'host{i}.example.com' for i in range(40)]})
        with self.assertRaises(ApprovalSummaryTooLong):
            self.summary({'name': 'n', 'url': 'https://example.com/' + 'p' * 600})

    def test_values_without_a_marker_are_cut_one_by_one(self):
        line = self.summary({'name': 'n' * 300, 'note': 'k' * 300, 'description': 'd' * 300})
        self.assertLessEqual(len(line), 500)
        for key in ('name', 'note', 'description'):
            self.assertIn(f'"{key}"', line)

    def test_without_markers_it_still_masks_and_cuts(self):
        line = _summarize({'url': 'https://u:p@a.example/' + 'y' * 300, 'name': 'n'}, {'type': 'object', 'properties': {}})
        self.assertNotIn('Destinations', line)
        self.assertIn('https://***@a.example/', line)
        self.assertLessEqual(len(line), 500)

    def test_empty_and_odd_input(self):
        self.assertEqual(_summarize(None, self.schema), '')
        self.assertEqual(_summarize({}, self.schema), '')
        self.assertEqual(_summarize({'method': 'POST', 'path': '/x', 'headers': {'a': 'b'}}, self.schema), '')
        self.assertLessEqual(len(self.summary({'name': 5, 'url': None, 'hosts': None, 'audience': 'x'})), 500)
        self.assertEqual(mask_url_secrets('no url here'), 'no url here')
