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
