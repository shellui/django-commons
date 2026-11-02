# shellui-django

Shared Django code that powers Shellui backend services (identity, email, storage, hosting, saas). The first published module turns a Django REST Framework API into a secure multi-tenant [Model Context Protocol](https://modelcontextprotocol.io/) server using OpenAPI operations tagged `mcp-tools` and `x-mcp` metadata.

## Install

```bash
pip install shellui-django[mcp]
```

The base package depends on Django and DRF. The `[mcp]` extra adds PyJWT, cryptography, and SimpleJWT helpers used by MCP authentication and signed internal calls.

## Quick start

1. Tag DRF views you want agents to call with the `mcp-tools` OpenAPI tag (or the `mcp_expose_tool` decorator).
2. Expose your drf-spectacular schema and construct an `McpServer` with your URLconf and a settings-driven service id in the agent token `scope` claim.
3. Mount the MCP HTTP handler on `/mcp` and validate agent JWTs (RS256, audience set to your service `{origin}/mcp` resource URL) before calling `McpServer.handle`.
4. Poll Identity for revocation lists using the signed internal helpers in `shellui_django.mcp.internal`, and wire `identity_revocation_check` on the server so revoked agents fail closed.

See `src/shellui_django/mcp/` for modules (routing, write gate, masking, OpenAPI tool builder, streamable HTTP server).

## Security

- **Token verification**: Agent access tokens must use RS256. Verify issuer, expiry, and that `aud` matches your service MCP resource URL (`https://your-service.example/mcp`).
- **Audience**: Each Shellui service has its own MCP resource indicator. Tokens minted for one service must not authorize another.
- **Tenant isolation**: Agent tokens carry a `company_id`. MCP tooling must not allow agents to override tenant scope via query or body parameters.
- **Write approvals**: Destructive or write operations can require human approval depending on agent access mode (`read_only`, `ask`, `full`).
- **Revocation**: Services should poll Identity for revoked agents and reject them immediately (fail closed when revocation data cannot be trusted).

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development

Requires Python 3.14+, [uv](https://docs.astral.sh/uv/), and the lockfile in this repository.

```bash
uv sync --all-groups
DJANGO_SETTINGS_MODULE=tests.django_settings uv run python -m django test shellui_django.mcp.tests --verbosity=1
uv run ruff check src
uv build
```

## License

MIT. See [LICENSE](LICENSE).
