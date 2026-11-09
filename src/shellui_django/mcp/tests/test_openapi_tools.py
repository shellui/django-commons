from django.test import SimpleTestCase

from shellui_django.mcp.openapi_tools import tools_from_schema


class OpenApiToolsPathParamTests(SimpleTestCase):
    def test_path_params_required_in_input_schema(self):
        schema = {
            'paths': {
                '/api/v1/companies/{company_id}/widgets/': {
                    'get': {
                        'tags': ['mcp-tools'],
                        'operationId': 'list_widgets',
                        'parameters': [
                            {
                                'in': 'query',
                                'name': 'limit',
                                'required': True,
                                'schema': {'type': 'integer'},
                            }
                        ],
                    },
                },
            },
        }
        tools = tools_from_schema(schema)
        self.assertEqual(len(tools), 1)
        tool = tools[0]
        self.assertIn('path_params', tool['inputSchema']['properties'])
        self.assertIn('path_params', tool['inputSchema']['required'])
        self.assertEqual(tool['_meta']['path_params'], ['company_id'])
        self.assertEqual(tool['_meta']['query_fields'], ['limit'])
        self.assertEqual(
            tool['inputSchema']['properties']['query']['properties']['limit']['type'],
            'integer',
        )


class OpenApiToolsBodyRefTests(SimpleTestCase):
    def test_request_body_ref_exposes_typed_fields(self):
        schema = {
            'components': {
                'schemas': {
                    'TemplateVersionCreateRequest': {
                        'type': 'object',
                        'properties': {
                            'subject': {'type': 'string'},
                            'preheader': {'type': 'string'},
                            'document': {},
                            'translations': {'description': 'Other languages'},
                            'theme': {'description': 'Theme map'},
                            'library_id': {'type': 'integer'},
                        },
                    },
                },
            },
            'paths': {
                '/api/v1/templates/{template_id}/versions': {
                    'post': {
                        'tags': ['mcp-tools'],
                        'operationId': 'api_v1_template_versions_create',
                        'summary': 'Create a draft template version',
                        'requestBody': {
                            'content': {
                                'application/json': {
                                    'schema': {
                                        '$ref': '#/components/schemas/TemplateVersionCreateRequest',
                                    }
                                }
                            }
                        },
                    },
                },
            },
        }
        tools = tools_from_schema(schema)
        self.assertEqual(len(tools), 1)
        tool = tools[0]
        body = tool['inputSchema']['properties']['body']
        self.assertEqual(
            set(body['properties']),
            {'subject', 'preheader', 'document', 'translations', 'theme', 'library_id'},
        )
        self.assertEqual(body['properties']['subject']['type'], 'string')
        self.assertEqual(body['properties']['library_id']['type'], 'integer')
        self.assertEqual(body['properties']['document']['type'], 'object')
        self.assertTrue(body['properties']['document']['additionalProperties'])
        self.assertEqual(body['properties']['theme']['type'], 'object')
        self.assertTrue(body['properties']['theme']['additionalProperties'])
        self.assertEqual(
            tool['_meta']['body_fields'],
            ['document', 'library_id', 'preheader', 'subject', 'theme', 'translations'],
        )

    def test_inline_body_properties_still_work(self):
        schema = {
            'paths': {
                '/api/v1/notes': {
                    'post': {
                        'tags': ['mcp-tools'],
                        'operationId': 'create_note',
                        'requestBody': {
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'properties': {'title': {'type': 'string'}},
                                        'required': ['title'],
                                    }
                                }
                            }
                        },
                    },
                },
            },
        }
        tool = tools_from_schema(schema)[0]
        body = tool['inputSchema']['properties']['body']
        self.assertEqual(body['properties']['title']['type'], 'string')
        self.assertEqual(body['required'], ['title'])
        self.assertEqual(tool['_meta']['body_fields'], ['title'])


class OpenApiToolsNestedRefTests(SimpleTestCase):
    def _body(self, props: dict, components: dict) -> dict:
        schema = {
            'components': {
                'schemas': {
                    **components,
                    'Req': {'type': 'object', 'properties': props},
                },
            },
            'paths': {
                '/api/v1/things': {
                    'post': {
                        'tags': ['mcp-tools'],
                        'operationId': 'create_thing',
                        'requestBody': {
                            'content': {
                                'application/json': {
                                    'schema': {'$ref': '#/components/schemas/Req'},
                                }
                            }
                        },
                    },
                },
            },
        }
        return tools_from_schema(schema)[0]['inputSchema']['properties']['body']['properties']

    def test_enum_ref_and_all_of_stay_strings(self):
        components = {'StatusEnum': {'type': 'string', 'enum': ['draft', 'live']}}
        body = self._body(
            {
                'status': {'$ref': '#/components/schemas/StatusEnum'},
                'status_wrapped': {'allOf': [{'$ref': '#/components/schemas/StatusEnum'}]},
            },
            components,
        )
        for key in ('status', 'status_wrapped'):
            self.assertEqual(body[key]['type'], 'string')
            self.assertEqual(body[key]['enum'], ['draft', 'live'])

    def test_nullable_blank_enum_one_of(self):
        components = {
            'StatusEnum': {'type': 'string', 'enum': ['draft', 'live']},
            'BlankEnum': {'enum': ['']},
            'NullEnum': {'enum': [None]},
        }
        body = self._body(
            {
                'status': {
                    'oneOf': [
                        {'$ref': '#/components/schemas/StatusEnum'},
                        {'$ref': '#/components/schemas/BlankEnum'},
                        {'$ref': '#/components/schemas/NullEnum'},
                    ]
                },
                'name': {'type': 'string', 'nullable': True},
            },
            components,
        )
        self.assertEqual(body['status']['type'], ['string', 'null'])
        self.assertEqual(body['status']['enum'], ['draft', 'live', '', None])
        self.assertEqual(body['name']['type'], ['string', 'null'])

    def test_nested_serializer_ref_is_typed_object(self):
        components = {
            'Child': {
                'type': 'object',
                'properties': {'x': {'type': 'integer'}, 'parent': {'$ref': '#/components/schemas/Child'}},
                'required': ['x'],
            },
        }
        body = self._body(
            {
                'child': {'$ref': '#/components/schemas/Child'},
                'children': {'type': 'array', 'items': {'$ref': '#/components/schemas/Child'}},
            },
            components,
        )
        self.assertEqual(body['child']['type'], 'object')
        self.assertEqual(body['child']['properties']['x']['type'], 'integer')
        self.assertEqual(body['child']['required'], ['x'])
        # Self-reference stops instead of recursing forever.
        self.assertTrue(body['child']['properties']['parent']['additionalProperties'])
        self.assertEqual(body['children']['items']['properties']['x']['type'], 'integer')
