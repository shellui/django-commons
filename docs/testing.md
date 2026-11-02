# Testing module (`shellui_django.testing`)

**Status: planned**

This package will hold shared Django test helpers extracted from Shellui services (fixtures, factories, and utilities used in more than one repo).

Today the module only exports an empty public API. Service-specific two-tenant isolation tests stay in each service until a shared pattern is agreed.

For MCP tests in this repo, see [mcp.md](mcp.md#testing-a-service-integration) and `tests/django_settings.py`.
