"""Collision-proof labels, array-level markers, refused placements, and the contract-test lint."""

from functools import partial

from django.test import SimpleTestCase

from shellui_django.mcp.approval_summary import (
    UNDECLARED_WARNING,
    ApprovalSummaryRefused,
    destination_paths,
    mask_url_secrets,
    summarize_arguments,
)
from shellui_django.mcp.destinations import (
    DestinationMarkerError,
    count_markers,
    lint_destination_names,
    readable_marker_count,
    validate_destination_schema,
)
from shellui_django.mcp.openapi_tools import tools_from_schema

D = {'type': 'string', 'x-mcp-destination': True}
S = {'type': 'string'}


def _sectioned(query=None, body=None) -> dict:
    return {
        'type': 'object',
        'properties': {
            'path': {'type': 'string', 'const': '/x'},
            'method': {'type': 'string', 'enum': ['POST']},
            'query': {'type': 'object', 'properties': query or {}},
            'body': {'type': 'object', 'properties': body or {}},
        },
    }


def _document(body_properties: dict, *, query: list | None = None) -> dict:
    return {
        'paths': {
            '/x': {
                'post': {
                    'tags': ['mcp-tools'],
                    'operationId': 'x_create',
                    'parameters': query or [],
                    'requestBody': {
                        'content': {'application/json': {'schema': {'type': 'object', 'properties': body_properties}}}
                    },
                }
            }
        }
    }


# The default is fail closed (undeclared). These tests are about the line itself, so they declare.
_summarize = partial(summarize_arguments, destinations_declared=True)

class LabelTests(SimpleTestCase):
    def test_an_unmarked_query_url_cannot_shadow_a_marked_body_url(self):
        schema = _sectioned(query={'url': S}, body={'url': D})
        for arguments in (
            {'query': {'url': 'https://good.example/'}, 'body': {'url': 'https://attacker.example/h'}},
            {'url': 'https://attacker.example/h'},
            {'body': {'url': 'https://attacker.example/h'}},
        ):
            with self.subTest(arguments=arguments):
                line = _summarize(arguments, schema)
                self.assertTrue(line.startswith('Destinations: {"url": "https://attacker.example/h"}'), line)

    def test_a_marked_name_in_both_sections_shows_both_with_distinct_labels(self):
        schema = _sectioned(query={'url': D}, body={'url': D})
        line = _summarize({'query': {'url': 'https://a.example/'}, 'body': {'url': 'https://b.example/'}}, schema)
        self.assertIn('"url": "https://a.example/"', line)
        self.assertIn('"url #2": "https://b.example/"', line)

    def test_a_property_literally_named_like_a_nested_path_does_not_collide_with_it(self):
        schema = _sectioned(body={'a.b': D, 'a': {'type': 'object', 'properties': {'b': D}}})
        line = _summarize({'body': {'a.b': 'https://one.example/', 'a': {'b': 'https://two.example/'}}}, schema)
        self.assertIn('https://one.example/', line)
        self.assertIn('https://two.example/', line)

    def test_nested_keys_are_labelled_from_the_schema_path_in_lists_of_objects(self):
        contacts = {'type': 'array', 'items': {'type': 'object', 'properties': {'email': D, 'name': S}}}
        line = _summarize(
            {'body': {'contacts': [{'email': 'a@x.example', 'name': 'A'}, {'email': 'b@x.example', 'name': 'B'}]}},
            _sectioned(body={'contacts': contacts}),
        )
        self.assertIn('"contacts[0].email": "a@x.example"', line)
        self.assertIn('"contacts[1].email": "b@x.example"', line)
        self.assertNotIn('x.example', line.split(' | ')[1])

    def test_an_undeclared_nested_key_is_never_a_destination_label(self):
        contacts = {'type': 'array', 'items': {'type': 'object', 'properties': {'email': D}}}
        line = _summarize(
            {'body': {'contacts': [{'email': 'a@x.example', 'contacts[0].email': 'evil@x.example'}]}},
            _sectioned(body={'contacts': contacts}),
        )
        self.assertEqual(line.split(' | ')[0], 'Destinations: {"contacts[0].email": "a@x.example"}')


class MarkedValueShapeTests(SimpleTestCase):
    schema = _sectioned(body={'url': D, 'name': S})

    def test_a_marked_string_sent_as_a_list_shows_each_item(self):
        line = _summarize({'body': {'url': ['https://a.example/', 'https://b.example/']}}, self.schema)
        self.assertIn('"url[0]": "https://a.example/"', line)
        self.assertIn('"url[1]": "https://b.example/"', line)

    def test_a_marked_string_sent_as_an_object_or_list_of_objects_is_refused(self):
        for value in ({'x': 'https://a.example/'}, [{'x': 'https://a.example/'}], ['https://a.example/', {'y': 1}]):
            with self.subTest(value=value), self.assertRaises(ApprovalSummaryRefused):
                _summarize({'body': {'url': value}}, self.schema)

    def test_an_array_level_marker_is_honoured_like_destination_paths_says(self):
        schema = _sectioned(body={'hosts': {'type': 'array', 'items': S, 'x-mcp-destination': True}})
        self.assertEqual(destination_paths(schema), {'hosts'})
        line = _summarize({'body': {'hosts': ['a.example', 'b.example']}}, schema)
        self.assertIn('"hosts[0]": "a.example"', line)
        self.assertIn('"hosts[1]": "b.example"', line)


class PlacementTests(SimpleTestCase):
    def test_markers_under_unsupported_keywords_are_refused_when_the_tools_are_built(self):
        cases = {
            'oneOf': {'u': {'oneOf': [D, {'type': 'integer'}]}},
            'anyOf': {'u': {'anyOf': [D, {'type': 'object', 'properties': {'a': S}}]}},
            'additionalProperties': {'u': {'type': 'object', 'additionalProperties': D}},
            'patternProperties': {'u': {'type': 'object', 'patternProperties': {'^x': D}}},
            'wrong type': {'u': {'type': 'integer', 'x-mcp-destination': True}},
            'object': {'u': {'type': 'object', 'x-mcp-destination': True, 'properties': {'a': S}}},
            'not true': {'u': {'type': 'string', 'x-mcp-destination': 'yes'}},
        }
        for name, body in cases.items():
            with self.subTest(name), self.assertRaises(DestinationMarkerError):
                tools_from_schema(_document(body))

    def test_a_marker_in_a_query_parameter_under_oneof_is_refused_too(self):
        parameter = {'name': 'u', 'in': 'query', 'schema': {'oneOf': [D, {'type': 'integer'}]}}
        with self.assertRaises(DestinationMarkerError):
            tools_from_schema(_document({}, query=[parameter]))

    def test_a_marker_through_ref_is_kept_and_counted(self):
        document = _document({'sub': {'$ref': '#/components/schemas/Sub'}})
        document['components'] = {'schemas': {'Sub': {'type': 'object', 'properties': {'to': D}}}}
        tool = tools_from_schema(document)[0]
        self.assertEqual(destination_paths(tool['inputSchema']), {'sub.to'})

    def test_validate_destination_schema_accepts_string_arrays_and_their_items(self):
        validate_destination_schema(_sectioned(body={'a': D, 'b': {'type': 'array', 'items': D}, 'c': {'type': ['string', 'null'], 'x-mcp-destination': True}}))

    def test_the_public_check_refuses_markers_it_never_reads(self):
        cases = {
            '$ref into $defs': {**_sectioned(body={'a': {'$ref': '#/$defs/X'}}), '$defs': {'X': D}},
            'tuple items': _sectioned(body={'a': {'type': 'array', 'items': [D, S]}}),
            'contains': _sectioned(body={'a': {'type': 'array', 'contains': D}}),
            'dependentSchemas': _sectioned(body={'a': {'type': 'object', 'dependentSchemas': {'b': {'properties': {'c': D}}}}}),
            'unevaluatedProperties': _sectioned(body={'a': {'type': 'object', 'unevaluatedProperties': D}}),
            'headers': {'type': 'object', 'properties': {'headers': {'type': 'object', 'properties': {'x': D}}}},
            'path': {'type': 'object', 'properties': {'path': D}},
            'a section node': {'type': 'object', 'properties': {'body': {**D, 'type': 'object', 'properties': {}}}},
            'a top-level definitions entry': {**_sectioned(body={'a': S}), 'definitions': {'X': D}},
        }
        for name, schema in cases.items():
            with self.subTest(name), self.assertRaises(DestinationMarkerError):
                validate_destination_schema(schema)

    def test_the_public_check_and_the_build_check_agree_on_a_supported_schema(self):
        schema = _sectioned(body={'a': D, 'b': {'type': 'array', 'items': D}, 'c': {'type': 'object', 'properties': {'d': D}}})
        validate_destination_schema(schema)
        self.assertEqual(count_markers(schema), 3)
        self.assertEqual(readable_marker_count(schema), 3)

    def test_tools_say_whether_their_destinations_are_declared(self):
        document = _document({'to': D})
        self.assertIs(tools_from_schema(document)[0]['_meta']['destinations_declared'], False)
        self.assertIs(tools_from_schema(document, destinations_declared=True)[0]['_meta']['destinations_declared'], True)


class WarningAndMaskingTests(SimpleTestCase):
    schema = _sectioned(body={'token_url': D, 'credentials': {'type': 'object', 'properties': {'host': D, 'password': S}}})

    def test_an_undeclared_tool_starts_with_a_warning(self):
        line = _summarize({'body': {'token_url': 'https://a.example/'}}, self.schema, destinations_declared=False)
        self.assertTrue(line.startswith(UNDECLARED_WARNING), line)
        self.assertIn('https://a.example/', line)

    def test_redaction_masks_siblings_only_not_declared_destinations(self):
        def redact(values):
            return {k: ('***' if 'token' in k or 'credential' in k else v) for k, v in values.items()}

        line = _summarize(
            {'body': {'token_url': 'https://a.example/t', 'credentials': {'host': 'smtp.evil.example', 'password': 'pw'}}},
            self.schema,
            redact=redact,
        )
        self.assertIn('"token_url": "https://a.example/t"', line)
        self.assertIn('"credentials.host": "smtp.evil.example"', line)
        self.assertIn('"credentials": "***"', line)
        self.assertNotIn('pw', line)

    def test_secret_query_parameters_in_urls_are_masked(self):
        for url, secret in (
            ('https://a.example/h?token=SECRET1', 'SECRET1'),
            ('https://a.example/h?x=1&key=SECRET2&y=2', 'SECRET2'),
            ('https://a.example/h?sig=SECRET3#frag', 'SECRET3'),
            ('https://a.example/h?X-Amz-Signature=SECRET4', 'SECRET4'),
            ('https://a.example/h?api_key=SECRET5;secret=SECRET6', 'SECRET5'),
        ):
            with self.subTest(url=url):
                self.assertNotIn(secret, mask_url_secrets(url))
                self.assertNotIn(secret, _summarize({'body': {'token_url': url}}, self.schema))
        self.assertIn('x=1', mask_url_secrets('https://a.example/h?x=1&key=S'))

    def test_secrets_in_a_url_fragment_are_masked(self):
        for url, secret in (
            ('https://a.example/cb#access_token=SECRET1&token_type=bearer', 'SECRET1'),
            ('https://a.example/cb#id_token=SECRET2', 'SECRET2'),
            ('https://a.example/cb?x=1#code=SECRET3&state=s', 'SECRET3'),
        ):
            with self.subTest(url=url):
                masked = mask_url_secrets(url)
                self.assertNotIn(secret, masked)
                self.assertIn('=***', masked)
        self.assertIn('state=s', mask_url_secrets('https://a.example/cb#access_token=S&state=s'))
        self.assertEqual(mask_url_secrets('https://a.example/page#section-2'), 'https://a.example/page#section-2')

    def test_parameters_are_masked_by_exact_name_or_word_not_by_substring(self):
        for visible in ('?authurl=https://idp.example/x', '?author=ann', '?keyword=shoes', '?monkey=1', '?tokenizer=bpe', '?codec=h264', '?signal=1'):
            with self.subTest(visible=visible):
                self.assertEqual(mask_url_secrets('https://a.example/h' + visible), 'https://a.example/h' + visible)
        for secret in ('?token=S', '?apiKey=S', '?api-key=S', '?X-Amz-Signature=S', '?accessToken=S', '?accesstoken=S', '?client_secret=S',
                       '?AUTH=S', '?auth_token=S', '?Password=S', '?sig=S', '?sessionToken=S'):
            with self.subTest(secret=secret):
                self.assertEqual(mask_url_secrets('https://a.example/h' + secret), 'https://a.example/h' + secret.split('=')[0] + '=***')

    def test_undeclared_is_the_default(self):
        line = summarize_arguments({'body': {'token_url': 'https://a.example/'}}, self.schema)
        self.assertTrue(line.startswith(UNDECLARED_WARNING), line)
        self.assertFalse(summarize_arguments({'body': {'token_url': 'https://a.example/'}}, self.schema, destinations_declared=True).startswith('WARN'))


class LintTests(SimpleTestCase):
    def _tool(self, body, *, read_only=False, name='svc_create'):
        return {'name': name, 'inputSchema': _sectioned(body=body), '_meta': {'read_only': read_only}}

    def test_a_new_unmarked_callback_url_fails(self):
        problems = lint_destination_names([self._tool({'callback_url': S, 'name': S})])
        self.assertEqual(len(problems), 1)
        self.assertIn('svc_create: callback_url looks like a destination', problems[0])

    def test_marked_allow_listed_and_read_only_fields_pass(self):
        tools = [
            self._tool({'callback_url': D, 'source_email': S, 'hosts': {'type': 'array', 'items': D}}),
            self._tool({'filter_email': S}, read_only=True, name='svc_list'),
        ]
        self.assertEqual(lint_destination_names(tools, {'svc_create': {'source_email'}}), [])

    def test_every_name_pattern_is_caught(self):
        names = ['x_url', 'x_uri', 'smtp_host', 'owner_email', 'sending_domain', 'allowed_origins', 'redirect_to', 'callback', 'endpoint', 'recipients']
        problems = lint_destination_names([self._tool({n: S for n in names})])
        self.assertEqual(len(problems), len(names), problems)

    def test_a_list_of_strings_is_checked_and_a_number_is_not(self):
        tool = self._tool({'extra_emails': {'type': 'array', 'items': S}, 'url_count': {'type': 'integer'}})
        problems = lint_destination_names([tool])
        self.assertEqual(len(problems), 1)
        self.assertIn('extra_emails', problems[0])

    def test_the_wider_names_are_caught_and_ordinary_names_are_not(self):
        caught = ['to', 'cc', 'bcc', 'reply_to', 'replyTo', 'address', 'emailAddress', 'ip_address', 'webhook', 'webhook_secret',
                  'target', 'target_host', 'href', 'server', 'smtp_server', 'hostname', 'phone', 'phone_number', 'dsn', 'sentry_dsn']
        ignored = ['name', 'auto', 'photo', 'description', 'total', 'token', 'status', 'note']
        problems = lint_destination_names([self._tool({n: S for n in caught + ignored})])
        flagged = {problem.split(': ')[1].split(' ')[0] for problem in problems}
        self.assertEqual(flagged, set(caught), problems)

    def test_an_unmarked_webhook_fails_and_a_marked_one_passes(self):
        self.assertEqual(len(lint_destination_names([self._tool({'webhook': S})])), 1)
        self.assertEqual(lint_destination_names([self._tool({'webhook': D})]), [])

    def test_a_stale_allow_list_entry_fails(self):
        tool = self._tool({'source_email': D})
        problems = lint_destination_names([tool], {'svc_create': {'source_email', 'gone'}, 'other_tool': {'x'}})
        self.assertEqual(len(problems), 3, problems)
