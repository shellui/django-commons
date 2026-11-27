"""Serializer fields that mark where a tool call sends data (``x-mcp-destination`` in OpenAPI).

Use one for every field that holds an address, URL, host, domain or origin the call reaches or
tells someone about. The gateway shows these values first in the approval prompt. For a list use
``serializers.ListField(child=McpDestinationCharField())``: the marker lands on the list items.
"""

from __future__ import annotations

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers


@extend_schema_field({'type': 'string', 'x-mcp-destination': True})
class McpDestinationCharField(serializers.CharField):
    pass


@extend_schema_field({'type': 'string', 'format': 'email', 'x-mcp-destination': True})
class McpDestinationEmailField(serializers.EmailField):
    pass


@extend_schema_field({'type': 'string', 'format': 'uri', 'x-mcp-destination': True})
class McpDestinationURLField(serializers.URLField):
    pass
