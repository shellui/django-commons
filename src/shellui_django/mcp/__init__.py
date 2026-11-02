"""MCP server layer for Shellui Django services."""

from shellui_django.mcp.decorators import mcp_expose_tool
from shellui_django.mcp.delegation import (
    DOWNSTREAM_TOKEN_AUDIENCE,
    DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS,
    DOWNSTREAM_TOKEN_SCOPE,
    DownstreamTokenRequestError,
    sign_downstream_token_request,
    verify_downstream_token_request,
)
from shellui_django.mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    REVOCATION_CACHE_SECONDS,
    REVOCATION_LIST_SCOPE,
    build_mcp_approval_assertion,
    build_mcp_revocation_list_response_assertion,
    parse_trusted_revocation_poll_response,
    verify_mcp_internal_assertion,
    verify_mcp_revocation_list_response,
)

__all__ = [
    'mcp_expose_tool',
    'DOWNSTREAM_TOKEN_AUDIENCE',
    'DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS',
    'DOWNSTREAM_TOKEN_SCOPE',
    'DownstreamTokenRequestError',
    'sign_downstream_token_request',
    'verify_downstream_token_request',
    'APPROVAL_AUDIENCE',
    'APPROVAL_SCOPE',
    'REVOCATION_CACHE_SECONDS',
    'REVOCATION_LIST_SCOPE',
    'build_mcp_approval_assertion',
    'build_mcp_revocation_list_response_assertion',
    'parse_trusted_revocation_poll_response',
    'verify_mcp_internal_assertion',
    'verify_mcp_revocation_list_response',
]
