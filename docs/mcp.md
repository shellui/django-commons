# MCP module (`shellui_django.mcp`)

Install with `pip install shellui-django[mcp]`.

## What MCP is

The [Model Context Protocol](https://modelcontextprotocol.io/) lets AI agents call tools over HTTP. In Shellui, each backend service can expose selected REST endpoints as MCP tools so agents act on behalf of a company with the same auth and tenancy rules as normal API clients.

## Architecture

```text
Agent JWT  -->  Your /mcp view
                      |
                      v
                 McpServer.handle  (verifies the bearer token, then JSON-RPC)
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

Each tool's input schema includes fixed `path` and `method`, optional `path_params`, `query`, and `body` objects derived from the operation. Request body and parameter schemas resolve OpenAPI `$ref` values against `components.schemas` (drf-spectacular often emits refs only). Typed fields are copied into the tool schema; untyped JSONField fragments become free-form objects. Extra query or body fields are rejected at call time.

### `McpServer`

Construct `McpServer` with:

- `schema_provider`: callable that returns the OpenAPI dict.
- `urlconf`: Django URL module used to resolve the inner request.
- `service_name`: short id (for example `saas`) that must appear in the agent token `scope` claim.
- `identity_issuer`: Identity issuer (`iss`) expected on agent access tokens. Compared without a trailing slash.
- `mcp_audience`: this service's MCP resource URL (`https://origin/mcp`). Must match token `aud`.
- `identity_jwks` or `identity_jwks_url`: verification keys for that token. Inline JWKS skips the network. A URL is fetched with the rules below.
- `identity_revocation_check`: required callable `(agent_id, company_id) -> bool`. Return true when the agent is revoked.
- Optional hooks: `on_call`, `approval_handler`, `approval_state`, `approval_consume`.

`handle` verifies the bearer token itself. The `agent_claims` argument is still accepted and is not used for authorization. Without issuer, audience, JWKS, or a valid bearer token, `handle` returns 401.

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
- **`tools/call`**: Routes using a short-lived cache keyed by exported tool name. Rejects the call when a tenant field in the arguments does not match the verified `company_id`. Otherwise forwards JSON-RPC to the configured URL with a minted downstream token. Does not re-run approvals or execute writes on behalf of downstream services.
- **`initialize`**: Returns `instructions` listing connected services for the agent.
- **Logging**: Logs service id, tool name, HTTP status, and exception types only. Never logs bearer tokens or tool arguments.

Helpers exported for host wiring and tests: `McpGatewayConfig`, `AggregatingMcpServer`, `merge_tool_catalog`, `gateway_instructions`, `public_mcp_tools`, `scope_service_ids`, `service_allowed`.

### Routing and path parameters

OpenAPI paths like `/api/v1/companies/{company_id}/items/` require a `path_params` object with exactly those keys. Values are URL-encoded. Slashes, braces, and empty values are rejected to block path injection.

Agents cannot retarget a tool: `path` and `method` in arguments must match the tool definition.

### Inner request auth

On `tools/call`, the server builds a DRF request with `APIRequestFactory`. It copies `HTTP_AUTHORIZATION` from the outer MCP request and calls `force_authenticate` with the verified token claims as `auth`. `request.user` is an authenticated principal for that agent id. The outer request's `user` and `auth` are not copied. Bodyless methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) do not attach a JSON body.

Your views should read the agent from `request.auth`.

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

`McpServer.handle` verifies agent access tokens (RS256, issuer, audience, JWKS) before it runs a tool. See Token verification below.

### Constants (not settings)

| Name | Value | Meaning |
|------|-------|---------|
| `REVOCATION_CACHE_SECONDS` | `30` | Default TTL in signed revocation list assertions. |
| `REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS` | `600` | Hard cap on `exp - iat` and on positive `cache_seconds` in signed revocation list responses (10 minutes). |
| JWKS in-memory cache | `300` s | TTL for fetched Identity JWKS documents in `identity_jwks`. |
| `JWKS_MAX_RESPONSE_BYTES` | `262144` | Maximum Identity JWKS response body (256 KiB). |

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
| `x-mcp-destination: true` | The value says where the call sends data (an address, URL, host, domain or origin). The gateway shows it first, in full, in the approval prompt. |

Keys ending in `_hint` are always redacted. Names matching `(password|secret|token|authorization|api_key|...)` are redacted. Email-like strings are redacted when `mcp_read` is not `sensitive`.

### Destination fields

Mark every field that holds a place the call reaches or tells someone about (a webhook URL, an email recipient, a redirect, an allowed origin or host, a sending domain) with `x-mcp-destination: true`. Use the serializer fields in `shellui_django.mcp.fields` (`McpDestinationCharField`, `McpDestinationEmailField`, `McpDestinationURLField`). For a list, use `serializers.ListField(child=McpDestinationEmailField())`: the marker lands on the list items. `tools_from_schema` keeps the marker on the tool's `inputSchema` property, including nested properties and array items.

`shellui_django.mcp.approval_summary.summarize_arguments(arguments, input_schema, max_length=500)` builds the approval line from those markers:

- Marked values come first, in full, as `Destinations: {"<label>": "<value>"}`. The label is built from the schema path (`audience.emails[1]`), never from a key the caller sent, so a caller cannot spoof or collide with it. Each list item has its own label.
- Non-ASCII and control characters are shown as escapes (a lookalike letter shows as `\u0430`), and `user:pass@` in any URL, in any value, is shown as `***@`.
- Every other value is cut on its own (60 characters) under `Arguments:`, so one long argument cannot push another out of view.
- If the marked values do not fit in the line, `ApprovalSummaryTooLong` is raised. Refuse the call; do not shorten a destination.

Nothing is guessed from key names. A tool whose destination fields are not marked shows them as ordinary arguments (masked and cut), so mark them.

### Read-only POST allowlist

`validate_read_only_post_tools(schema, allowlist=frozenset({...}))` enforces that every POST operation with `x-mcp.read_only` has its `operationId` in the allowlist. Call this at startup in services that use read-only POST tools.

## Agent token claims

`handle` reads these claims from the verified bearer token:

| Claim | Default | Role |
|-------|---------|------|
| `agent_id` | required | Identity of the agent. |
| `company_id` | optional | Tenant id from the verified token. Tool arguments that include a company id must match it. Passed to revocation checks and approval payloads. |
| `scope` | required | Space-separated service ids; must include `service_name`. |
| `mcp_access` | `read_only` | `read_only` or `full` (or legacy `ask`). |
| `mcp_read` | `safe` | `safe` or `sensitive` (response masking). |
| `mcp_destructive` | false | Reserved for hosts; does **not** skip destructive approval in `decide_write`. Every destructive tool call still goes through the approval hooks. |
| `mcp_gateway_delegated` | omitted | Object `{"action": "<tool name>", "exp": <unix seconds>}`. Skips a second approval only when `action` is the tool being called and `exp` is still in the future. `true` and any other shape do not skip approval. |

Numeric claims (for example `company_id`) use normal JSON numbers. `0` is a real value: treat a present `0` and a missing claim as different; do not collapse them in verification logic.

## Access modes and approvals

Write gate logic lives in `decide_write`:

| `mcp_access` | Safe methods (GET, HEAD, OPTIONS) | Other methods |
|--------------|-------------------------------------|---------------|
| `read_only` | Allowed | Blocked unless `x-mcp.read_only` on the tool |
| `ask` | Allowed | Same as `full` for this library (needs approval for writes unless the tool is read-only); prefer `full` for new agents |
| `full` | Allowed | Non-destructive writes allowed; destructive tools always need approval (fresh single-use human approval, `mcp_destructive` does not bypass) |

When approval is needed, `McpServer` builds an `approval_payload` (agent, company, service, tool name, arguments, hash, path, method) and:

1. If `approval_state` returns `executed`, the call fails (approval already used).
2. If `approved`, `approval_consume(approval_id, payload)` must return true to proceed.
3. If `pending`, returns MCP error with `meta.status: pending`.
4. If not granted and `approval_handler` is set, it may create a pending approval and return `meta.approval_id`.
5. Otherwise the call fails with the gate reason.

A downstream service skips that second approval only when the agent token's `mcp_gateway_delegated` object names this tool in `action` and `exp` is a Unix timestamp still in the future. There is no extra clock leeway on that `exp`. A boolean `mcp_gateway_delegated` does not skip approval.

Wire these callbacks to your Identity approval-state and consume HTTP endpoints. Use `build_mcp_approval_assertion` when the service calls Identity to create an approval (audience `shellui-mcp-approval`, scope `mcp.approval.create`).

**Regional / delegated authority (optional, last parameters in Python):** `grant_version` (`int | None`), `global_company_id` (`str | None`), `company_binding_version` (`int | None`). Detect presence with `is not None` only. Do not use truthiness on `company_binding_version` or `grant_version` (`0` is valid). **Personal (legacy):** omit both `global_company_id` and `company_binding_version`; that means a tenant-scoped row without global delegation rollover. You may pass `grant_version` as a non-negative int (including `0`) or omit it when the JWT should have no `grant_version` claim (no default `0`). **Delegated:** pass `global_company_id`, `company_binding_version` (explicit `0` allowed), and `grant_version` (all required). Strict Identity services should pass the full delegated triple for global agents. The library keeps `None` optional on the signature so 0.4.0 call sites still import. `bool` is rejected for numeric fields. There is no `**extra_claims` escape hatch. Reserved claim names cannot be overridden by an arbitrary dict.

Other internal assertion helpers (RS256 via `JWT_SIGNING_KEY` or explicit `private_key_pem` / `kid` / `issuer` kwargs):

| Helper | Audience | Scope |
|--------|----------|-------|
| `build_mcp_call_log_assertion` | `shellui-mcp-call-log` | `mcp.call_log.create` |
| `build_mcp_revocation_assertion` | `shellui-mcp-revocation` | `mcp.revocation.read` |

Verify incoming assertions with `verify_mcp_internal_assertion` (alias of `verify_rs256_mcp_assertion`). Pass the caller JWKS document or public PEM, the expected caller issuer (must match `iss`), audience, scope, and Identity public URL as `expected_target`. When `expected_target` is set, the assertion `target` must equal it after stripping a trailing slash. An empty or missing `target` does not match. RS256 only; optional `register_jti` for replay protection.

Service-to-Identity assertions are still signed with the **caller's** RS256 material (`JWT_SIGNING_KEY` or explicit PEM/`kid`); Identity verifies with the caller's JWKS. Use the same pattern for regional authority fields: sign only through `build_mcp_*` helpers so proofs stay aligned with verification.

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

`McpServer.handle` reads `Authorization: Bearer` and verifies it before any tool runs:

1. RS256 via `decode_identity_rs256_jwt`, using `identity_issuer` and `identity_jwks` or `identity_jwks_url`. The decoder always requires `exp`, `iat`, `sub`, `scope`, and `jti`, and `handle` also requires `agent_id`. Pass extra claim names only in `require_claims` when calling the decoder yourself; they are unioned with that core set. Decoded `iat` and `exp` are normalized to non-negative integers (strict types after verify; digit strings from legacy issuers are accepted).
2. Audience per [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html): `mcp_audience` must match token `aud` and `access_token_audience_matches`. Use `mcp_resource_from_origin` to build the expected value.
3. A missing or invalid token returns 401. Callers may still pass `agent_claims`; those values are not used for authorization.

Fetched JWKS documents use the configured URL only. Redirects are not followed. The scheme must be `https`, except `http` while Django `DEBUG` is true. Other schemes are rejected. The response body is capped at `JWKS_MAX_RESPONSE_BYTES` (256 KiB). `timeout` must be positive and defaults to 10 seconds.

Resource URLs must be absolute `https` (or `http` on loopback, private, or CGNAT/`100.64.0.0/10` IP literals for local/LAN/Tailscale), path exactly `/mcp`, no query or fragment. Public hostnames over plain `http` are rejected.

## Tenant isolation

`company_id` comes from the verified bearer token. On `tools/call`, tenant fields in the arguments must match that id. Keys are `company_id`, `companyId`, and `company-id`, at any depth in `path_params`, `query`, and `body`. A mismatch is a JSON-RPC invalid-params error and the inner view is not called. The aggregating gateway applies the same check before it forwards a call. A token with no `company_id` does not match a tenant field. `0` is a real company id.

Views should still read the company from `request.auth` for any field this check does not see.

## Revocation

Services poll Identity for revoked agents. Identity should sign responses with `build_mcp_revocation_list_response_assertion` (RS256 via `JWT_SIGNING_KEY`).

Optional **last** kwargs `revocation_policy_version` and `max_active_grant_version` (non-negative `int` or `None` to omit) are copied into the signed JWT. **New fields** use JSON integers in the JWT and body (exact type parity). **Legacy HTTP boundary only:** top-level envelope keys may still use a decimal digit string (for example `"0"`) for older services; signed JWT values may use the same legacy string form for those policy integers. Reject bool, float, and non-digit strings. If a key is absent from the JWT, the body must not add it. If the JWT includes a key, the body must echo it. Unsigned numbers never fill a missing signed claim. `verify_mcp_revocation_list_response` returns both policy keys: `int` when signed, else `None`. `parse_trusted_revocation_poll_response` still returns `(revoked_ids, cache_seconds, agent_rows)`; rows may include helper fields added after verification. Assertions require `jti`, `iat` and `exp` as non-negative Unix seconds (ints after decode;
legacy digit strings are coerced after verify), `exp` strictly after `iat`,
`cache_seconds` positive and at most `REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS`,
and `exp - iat` at most that same cap. There is no separate maximum age on `iat` beyond
that span and the leeway described below (lists may stay cache-stable for the poll window).

After decode, times must fall within the same clock window PyJWT uses
(`IDENTITY_RS256_LEEWAY_SECONDS`, 5 seconds): not issued in the future beyond leeway,
not expired beyond leeway. Decode uses that leeway so verification stays consistent.

**Per-agent snapshots (`agents[]`):** delegated rows need `global_company_id`, `company_binding_version`, and `grant_version`. Personal rows omit the global pair (or use JSON `null`). **Pair rule:** both global fields absent, or both set. `0` is valid for `company_binding_version`. Use `is not None`, not truthiness. Optional personal `grant_version` is not compared to `max_active_grant_version`. For delegated rows, if `grant_version` is greater than the signed `max_active_grant_version`, the row is **not** trusted for binding: `mcp_authority_snapshot_rejected` is true, fingerprint is `null`. The cap is a signed policy snapshot, not permission to widen grants. Match `agent_id` with verified tenant and binding before you trust a row. After checks, delegated rows that pass add `mcp_authority_snapshot_fingerprint` (SHA-256 hex of sorted `company_binding_version`, `global_company_id`, `grant_version` JSON). Personal rows use `null` fingerprint. Compare the raw signed `agents` list to the HTTP body before you rely on helper fields.

Company-bound rows are signed: compare the JWT `agents` claim to the JSON body, then read normalized rows from `verify_mcp_revocation_list_response`.

Consumers should use `parse_trusted_revocation_poll_response` or `verify_mcp_revocation_list_response`:

- Verifies the embedded assertion with Identity JWKS (audience `shellui-mcp-revocation`, scope `mcp.revocation.list`, subject `identity`).
- Cross-checks `revoked_agent_ids`, `cache_seconds`, and `agents` between the JSON body and the JWT, and optional version fields when Identity includes them in the assertion.
- On any error, treat data as untrusted (**fail closed**).

Pass `identity_revocation_check(agent_id, company_id)` into `McpServer`. Return `True` when the agent is revoked (`403`, `agent_revoked`). The hook is required: if it is missing or raises, `handle` responds with `403` and `revocation_unavailable`. An invalid `company_id` on the token is rejected before the hook runs.

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

- [ ] `McpServer` constructed with `identity_issuer`, `mcp_audience`, and JWKS (`identity_jwks` or `identity_jwks_url`).
- [ ] `aud` matches this service's `{origin}/mcp` resource URL only.
- [ ] `scope` includes only services this deployment should expose.
- [ ] Revocation poll responses verified with `parse_trusted_revocation_poll_response`; fail closed if verification fails.
- [ ] `identity_revocation_check` wired and tested (requests are rejected when it is missing).
- [ ] Views still read `company_id` from `request.auth` for fields outside tool arguments.
- [ ] Only intentional endpoints tagged `mcp-tools`.
- [ ] `x-mcp-secret` / `x-mcp-sensitive` set on PII and credential fields.
- [ ] `x-mcp-destination` set on every field that holds an address, URL, host, domain or origin.
- [ ] Read-only POST tools listed in `validate_read_only_post_tools` allowlist.
- [ ] Approval hooks implemented for non-destructive `full` writes and for **every** destructive tool call in `full` mode.
- [ ] `HTTP_AUTHORIZATION` on MCP requests matches what inner views expect.
- [ ] Production cache configured for MCP rate limits when enabled.

Report issues via [SECURITY.md](../SECURITY.md).
