# MCP module (`shellui_django.mcp`)

Install with `pip install shellui-django[mcp]`.

## What MCP is

The [Model Context Protocol](https://modelcontextprotocol.io/) lets AI agents call tools over HTTP. In Shellui, each backend service can expose selected REST endpoints as MCP tools so agents act on behalf of a company with the same auth and tenancy rules as normal API clients.

## Architecture

```text
Agent JWT  -->  Your /mcp view (verify token, build agent_claims)
                      |
                      v
                 McpServer.handle  (JSON-RPC: initialize, tools/list, tools/call)
                      |
        tools/list <-- OpenAPI schema (operations tagged mcp-tools)
                      |
        tools/call --> validate args, write gate, optional approvals
                      |
                      v
                 DRF view via urlconf (inner request)
```

### OpenAPI-driven tools

`tools_from_schema` reads a drf-spectacular OpenAPI document. Only operations whose `tags` include `mcp-tools` become tools. Tool names come from `operationId` (slugified) or `{method}_{path}`.

Each tool's input schema includes fixed `path` and `method`, optional `path_params`, `query`, and `body` objects derived from the operation. Extra query or body fields are rejected at call time.

### `McpServer`

Construct `McpServer` with:

- `schema_provider`: callable that returns the OpenAPI dict.
- `urlconf`: Django URL module used to resolve the inner request.
- `service_name`: short id (for example `saas`) that must appear in the agent token `scope` claim.
- Optional hooks: `identity_revocation_check`, `on_call`, `approval_handler`, `approval_state`, `approval_consume`.

Your HTTP view should verify the agent JWT, then call `server.handle(request, agent_claims=claims)`.

Supported JSON-RPC methods:

- `initialize` returns protocol version `2024-11-05`.
- `tools/list` returns public tool metadata (internal `_meta` is stripped).
- `tools/call` runs one tool.

### Aggregating gateway (`shellui_django.mcp.gateway`)

Use `AggregatingMcpServer` when one MCP endpoint should expose tools from several Shellui services (for example the ai-service gateway). It subclasses `McpServer`: local tools still run through the normal OpenAPI path (write gate, approvals, call logs). Remote tools are discovered and invoked over HTTP on each downstream service's `/mcp` URL.

```text
Agent JWT  -->  Gateway /mcp (AggregatingMcpServer)
                      |
        tools/list ----+---- local OpenAPI tools
                      |
                      +---- HTTP tools/list per allowed downstream service
                      |
        tools/call -----+---- local: super().handle (unchanged)
                      |
                      +---- HTTP tools/call on configured service URL
```

Wire the gateway with `McpGatewayConfig`:

| Field | Role |
|-------|------|
| `get_service_urls` | Callable returning `{service_id: mcp_url}` from server config only (never from client input). |
| `resolve_agent` | Load the agent row for `agent_id` + `company_id` in claims; return `None` when missing. |
| `mint_downstream_token` | Obtain an RS256 access token for the agent with `aud` set to the target MCP resource URL ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)), typically by calling Identity with `sign_downstream_token_request` from `shellui_django.mcp.delegation`. |
| `local_service_id` | Service id for tools handled locally (must match `service_name` on the server). |
| `tools_cache_ttl_seconds` | Cache TTL for downstream tool catalogs and route map (default 30). |
| `downstream_timeout_seconds` | HTTP timeout for downstream MCP calls (default 5). |
| `instructions_title` | First line of `initialize` instructions (default `Shellui MCP gateway.`). |
| `cache` | Optional cache backend (defaults to Django's cache). |

Behavior:

- **`tools/list`**: Merges local tools with each allowed downstream catalog. Allowed means the service id is in both JWT `scope` and the agent's `services_allowed` list. Downstream list failures omit that service only.
- **Tool names**: Downstream tools keep their name when unique. Collisions become `{service_id}__{name}` (then `{service_id}__{name}__gateway` if still colliding).
- **`tools/call`**: Routes using a short-lived cache keyed by exported tool name. Forwards JSON-RPC to the configured URL with a minted downstream token. Does not re-run approvals or execute writes on behalf of downstream services.
- **`initialize`**: Returns `instructions` listing connected services for the agent.
- **Logging**: Logs service id, tool name, HTTP status, and exception types only. Never logs bearer tokens or tool arguments.

Helpers exported for host wiring and tests: `McpGatewayConfig`, `AggregatingMcpServer`, `merge_tool_catalog`, `gateway_instructions`, `public_mcp_tools`, `scope_service_ids`, `service_allowed`.

### Routing and path parameters

OpenAPI paths like `/api/v1/companies/{company_id}/items/` require a `path_params` object with exactly those keys. Values are URL-encoded. Slashes, braces, and empty values are rejected to block path injection.

Agents cannot retarget a tool: `path` and `method` in arguments must match the tool definition.

### Inner request auth passthrough

On `tools/call`, the server builds a DRF request with `APIRequestFactory`. It copies `HTTP_AUTHORIZATION` from the outer MCP request and calls `force_authenticate` with the outer request's `user` and `auth`. If `auth` is missing, agent claims are used as `auth`. Bodyless methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) do not attach a JSON body.

Your views should read the agent from `request.auth` like any other DRF endpoint.

## Settings reference

The MCP code reads these Django settings. Do not rely on settings not listed here.

### Django `settings`

| Setting | Default | Used for |
|---------|---------|----------|
| `AUTH_RATE_LIMIT_ENABLED` | `True` | When false, per-agent MCP rate limiting is skipped. |
| `MCP_RATE_LIMITS` | `{}` | Rate limit config. Uses `limits['mcp_agent']` or `limits['default']` or `{limit: 120, window: 60}`. |
| `JWT_ISSUER` | none | Fallback Identity issuer when SimpleJWT `ISSUER` is empty (revocation list verification). |
| `JWT_ISSUER` | none | Public issuer URL on RS256 service-issued internal assertions (`build_mcp_*_assertion`); preferred over SimpleJWT `ISSUER`. |
| `JWT_ACTIVE_KEY_ID` | `''` | Fallback `kid` when `JWT_SIGNING_KEY.kid` is unset. |
| `JWT_SIGNING_KEY` | none | Object with `private_pem` and optional `kid`. Required for service-issued internal assertions and on Identity for revocation list responses. |

### SimpleJWT (`SIMPLE_JWT` / `api_settings`)

| Setting | Used for |
|---------|----------|
| `ISSUER` | Fallback issuer on service-issued internal assertions when `JWT_ISSUER` is empty. |

Service-issued internal assertions and Identity verification never use SimpleJWT `SIGNING_KEY` or `ALGORITHM`.

Agent access tokens are verified in your MCP view (not inside `McpServer`). Use RS256 and Identity JWKS via `decode_identity_rs256_jwt` and audience checks via `access_token_audience_matches` (see below).

### Constants (not settings)

| Name | Value | Meaning |
|------|-------|---------|
| `REVOCATION_CACHE_SECONDS` | `30` | Default TTL in signed revocation list assertions. |
| JWKS in-memory cache | `300` s | TTL for fetched Identity JWKS documents in `identity_jwks`. |

## Tagging views and OpenAPI operations

### Expose an operation as a tool

1. Add the `mcp-tools` tag to the OpenAPI operation (via DRF `@extend_schema` / spectacular config), **or**
2. Wrap the view with `@mcp_expose_tool` from `shellui_django.mcp` (sets metadata; still requires the tag in the published schema for `tools_from_schema`).

Only tag endpoints that are safe for agents. Do not tag staff-only or internal routes.

Optional decorator kwargs: `name`, `description` (stored on `_mcp_tool_meta`).

### Operation extension `x-mcp`

On the OpenAPI operation object:

| Field | Effect |
|-------|--------|
| `read_only: true` | POST (or other writes) are treated as read-only for the write gate. Read-only agents may call them. |
| `destructive: true` | Marks the tool destructive (with tag-based detection below). |

If `x-mcp` is absent, `read_only` is false and `destructive` follows HTTP method tags only.

Destructive without `x-mcp.destructive`: add OpenAPI tag `destructive` or `mcp-destructive` on the operation.

### Schema field extensions (masking)

On JSON schema properties in request or response bodies:

| Extension | Effect |
|-----------|--------|
| `x-mcp-secret: true` | Field is always redacted in logs and MCP responses. |
| `x-mcp-sensitive: true` | Redacted unless the agent token has `mcp_read: sensitive`. |

Keys ending in `_hint` are always redacted. Names matching `(password|secret|token|authorization|api_key|...)` are redacted. Email-like strings are redacted when `mcp_read` is not `sensitive`.

### Read-only POST allowlist

`validate_read_only_post_tools(schema, allowlist=frozenset({...}))` enforces that every POST operation with `x-mcp.read_only` has its `operationId` in the allowlist. Call this at startup in services that use read-only POST tools.

## Agent token claims

Your MCP view must pass verified claims into `handle`. Claims read by this library:

| Claim | Default | Role |
|-------|---------|------|
| `agent_id` | required | Identity of the agent. |
| `company_id` | optional | Tenant id passed to revocation checks and approval payloads. |
| `scope` | required | Space-separated service ids; must include `service_name`. |
| `mcp_access` | `read_only` | `read_only`, `ask`, or `full`. |
| `mcp_read` | `safe` | `safe` or `sensitive` (response masking). |
| `mcp_destructive` | false | When true and `mcp_access` is `full`, destructive tools skip the approval gate. |

## Access modes and approvals

Write gate logic lives in `decide_write`:

| `mcp_access` | Safe methods (GET, HEAD, OPTIONS) | Other methods |
|--------------|-------------------------------------|---------------|
| `read_only` | Allowed | Blocked unless `x-mcp.read_only` on the tool |
| `ask` | Allowed | Needs approval unless tool is read-only |
| `full` | Allowed | Allowed; destructive ops need approval unless `mcp_destructive` is true |

When approval is needed, `McpServer` builds an `approval_payload` (agent, company, service, tool name, arguments, hash, path, method) and:

1. If `approval_state` returns `executed`, the call fails (approval already used).
2. If `approved`, `approval_consume(approval_id, payload)` must return true to proceed.
3. If `pending`, returns MCP error with `meta.status: pending`.
4. If not granted and `approval_handler` is set, it may create a pending approval and return `meta.approval_id`.
5. Otherwise the call fails with the gate reason.

Wire these callbacks to your Identity approval-state and consume HTTP endpoints. Use `build_mcp_approval_assertion` when the service calls Identity to create an approval (audience `shellui-mcp-approval`, scope `mcp.approval.create`).

Other internal assertion helpers (RS256 via `JWT_SIGNING_KEY` or explicit `private_key_pem` / `kid` / `issuer` kwargs):

| Helper | Audience | Scope |
|--------|----------|-------|
| `build_mcp_call_log_assertion` | `shellui-mcp-call-log` | `mcp.call_log.create` |
| `build_mcp_revocation_assertion` | `shellui-mcp-revocation` | `mcp.revocation.read` |

Verify incoming assertions with `verify_mcp_internal_assertion` (alias of `verify_rs256_mcp_assertion`). Pass the caller JWKS document or public PEM, the expected caller issuer (must match `iss`), audience, scope, and Identity public URL as `expected_target`. RS256 only; optional `register_jti` for replay protection.

### Downstream MCP token delegation (`shellui_django.mcp.delegation`)

When the ai-service gateway (or another aggregating host) needs Identity to mint an RS256 agent access token for a downstream service `/mcp` URL, it signs a short-lived request JWT instead of minting that token locally.

| Constant | Value |
|----------|-------|
| `DOWNSTREAM_TOKEN_AUDIENCE` | `shellui-mcp-downstream-token` |
| `DOWNSTREAM_TOKEN_SCOPE` | `mcp.downstream_token.mint` |
| `DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS` | `60` |

**Gateway (caller):** `sign_downstream_token_request(private_key_pem, kid, issuer, agent_id, company_id, resource, ttl)` with `ttl` from 1 to 60 seconds. Claims: `iss`, `aud`, `scope`, `agent_id`, `company_id`, `resource`, `jti`, `iat`, `exp`. Send the JWT as `Authorization: Bearer …` to Identity's downstream token mint endpoint together with the same `agent_id`, `company_id`, and `resource` in the JSON body.

**Identity (verifier):** `verify_downstream_token_request(token, public_jwks_or_pem, expected_issuer)` accepts inline JWKS or a PEM public key, allows RS256 only (rejects HS* and `none`), enforces all required claims, caps lifetime at 60 seconds (with a small clock leeway), and returns the verified claims. Use `claims['jti']` to enforce single use. Never log the raw JWT.

Raises `DownstreamTokenRequestError` on failure (check `.status`, default 401).

## Token verification (agent access tokens)

This library does not verify agent bearer tokens inside `McpServer`. In your `/mcp` view:

1. Require RS256. Use `decode_identity_rs256_jwt` with Identity issuer and JWKS (`{issuer}/.well-known/jwks.json`, or pass `jwks_url` / inline `jwks`).
2. Check audience per [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html): the JWT `aud` must match this service's MCP resource URL (`https://your-origin/mcp`). Use `mcp_resource_from_origin` to build the expected value and `access_token_audience_matches` to compare.
3. Parse required claims (`agent_id`, `scope`, etc.) and reject missing or invalid tokens before calling `handle`.

Resource URLs must be absolute `https` (or `http` on loopback only), path exactly `/mcp`, no query or fragment.

## Tenant isolation

`company_id` must come from the verified JWT only. The MCP layer forwards `path_params`, `query`, and `body` to your views as the agent supplied them. It does not compare path `company_id` to the token.

**Service rule:** enforce that URL and payload tenant fields match `request.auth['company_id']`. Never trust a company id from tool arguments alone.

## Revocation

Services poll Identity for revoked agents. Identity should sign responses with `build_mcp_revocation_list_response_assertion` (RS256 via `JWT_SIGNING_KEY`).

Consumers should use `parse_trusted_revocation_poll_response` or `verify_mcp_revocation_list_response`:

- Verifies the embedded assertion with Identity JWKS (audience `shellui-mcp-revocation`, scope `mcp.revocation.list`, subject `identity`).
- Cross-checks `revoked_agent_ids`, `cache_seconds`, and `agents` between the JSON body and the JWT.
- On any error, treat data as untrusted (**fail closed**).

Pass a callable `identity_revocation_check(agent_id, company_id)` into `McpServer`. Return `True` when the agent is revoked. `handle` responds with `403` and `agent_revoked`.

Default cache hint in assertions: 30 seconds (`REVOCATION_CACHE_SECONDS`).

## Rate limiting

When `AUTH_RATE_LIMIT_ENABLED` is true, each `agent_id` is limited using Django's cache backend. Over-limit requests get HTTP 429 and JSON-RPC error `rate_limited`.

## Testing a service integration

1. Copy patterns from `tests/django_settings.py` (cache, `SIMPLE_JWT`, disable rate limits with `AUTH_RATE_LIMIT_ENABLED = False`).
2. Run this package's tests:  
   `DJANGO_SETTINGS_MODULE=tests.django_settings uv run python -m django test shellui_django.mcp.tests`
3. In your service, unit-test `McpServer` with a stub `schema_provider`, your `ROOT_URLCONF`, and `RequestFactory` posts to `/mcp`.
4. Test write gates and approvals by varying `mcp_access` and hook return values.
5. Test revocation by returning `True` from `identity_revocation_check`.
6. Test RS256 paths with the helpers in `shellui_django.mcp.tests.rs256_helpers` as a reference.

## Security checklist

- [ ] Agent JWT verified with RS256 and Identity JWKS before `McpServer.handle`.
- [ ] `aud` matches this service's `{origin}/mcp` resource URL only.
- [ ] `scope` includes only services this deployment should expose.
- [ ] Revocation poll responses verified with `parse_trusted_revocation_poll_response`; fail closed if verification fails.
- [ ] `identity_revocation_check` wired and tested.
- [ ] Tenant enforced in views: `company_id` from JWT, not from tool args alone.
- [ ] Only intentional endpoints tagged `mcp-tools`.
- [ ] `x-mcp-secret` / `x-mcp-sensitive` set on PII and credential fields.
- [ ] Read-only POST tools listed in `validate_read_only_post_tools` allowlist.
- [ ] Approval hooks implemented for `ask` mode and destructive `full` mode.
- [ ] `HTTP_AUTHORIZATION` on MCP requests matches what inner views expect.
- [ ] Production cache configured for MCP rate limits when enabled.

Report issues via [SECURITY.md](../SECURITY.md).
