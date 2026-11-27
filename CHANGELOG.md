# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).
Releases are tagged `vX.Y.Z` and published to PyPI as `shellui-django`.
Breaking changes bump the major version (minor while below 1.0.0), so services can pin a compatible range.

<!---
## [Unreleased] - yyyy-mm-dd

### ✨ Feature – for new features
### 🛠 Improvements – for general improvements
### 🚨 Changed – for changes in existing functionality
### ⚠️ Deprecated – for soon-to-be removed features
### 📚 Documentation – for documentation update
### 🗑 Removed – for removed features
### 🐛 Bug Fixes – for any bug fixes
### 🔒 Security – in case of vulnerabilities
### 🏗 Chore – for tidying code

See for sample https://raw.githubusercontent.com/favoloso/conventional-changelog-emoji/master/CHANGELOG.md
-->

## [0.9.0] - 2026-11-28

### ✨ Feature

- `x-mcp-destination: true` marks a tool property that says where a call sends data (a URL, an email, a host, a redirect target). `tools_from_schema` keeps it on the tool's `inputSchema`, on nested properties and on array items. `shellui_django.mcp.fields` has `McpDestinationCharField`, `McpDestinationEmailField` and `McpDestinationURLField` to set it on a serializer field, and `destination_paths(input_schema)` lists the marked paths of a tool, for service tests.
- The marker is checked when the tools are built. A marker the approval summary cannot read (under `oneOf`, `anyOf`, `allOf`, `additionalProperties`, `patternProperties`, `$ref` into `$defs`, tuple `items`, `contains`, `dependentSchemas`, `unevaluatedProperties`, under `headers` or `path`, or on an object or a number) raises `DestinationMarkerError`. `validate_destination_schema` runs the same count for a service that builds its own schema.
- `tools_from_schema(schema, destinations_declared=True)` sets `_meta.destinations_declared`, so a service says that it has marked its destinations.
- `shellui_django.mcp.approval_summary.summarize_arguments(arguments, input_schema, max_length=500, *, destinations_declared=False, redact=None)` builds the one-line summary a person reads before approving a call:
  - marked values come first, in full, under labels built from the schema path (never from a key the caller chose), each list item on its own, and an array-level marker marks its items;
  - a name sent under two sections or flat is checked against every declaration, so an unmarked field cannot hide a marked one;
  - a marked field that receives an object is refused with `ApprovalSummaryRefused`, and destinations that do not fit raise `ApprovalSummaryTooLong`, so a caller refuses the call instead of shortening a destination;
  - non-ASCII and control characters show as escapes, `user:pass@` is masked in every value, and credential-looking query and fragment parameters (`?token=`, `#access_token=`, `;jsessionid=`, percent-encoded names included) are masked by name or by word, so `?auth_url=` stays visible;
  - other values are cut one by one, and a `redact` callback masks them without ever seeing a destination;
  - the line starts with a warning when `destinations_declared` is false (the default), and when a tool that declared its destinations has no marker and an argument holds an address.
- `shellui_django.mcp.destinations.lint_destination_names(tools, allow=...)` is a check for a service's contract test. It fails on a write-tool field whose name looks like a destination (`url`, `uri`, `host`, `hostname`, `email`, `domain`, `endpoint`, `recipient`, `dsn`, numbered forms such as `url2`, names containing `redirect`, `callback`, `origin`, `webhook`, `address`, `target`, `href`, `server`, `phone`, `link` or `destination`, and `to`, `cc`, `bcc`, `reply_to`, `send_to`) that is neither marked nor on an allow-list with a reason. A stale allow-list entry fails too.

### 🏗 Chore

- The `mcp` extra now includes `drf-spectacular==0.30.0`, which every Shellui service already pins, for the new fields.
- Release workflow: the build backend is pinned (`hatchling==1.33.0` in `build-system.requires`, and `requirements-build.txt` with hashes, installed with `--require-hashes --only-binary :all:` and used without build isolation). `publish-pypi.yml` has a read-only build-and-verify job and a publish job with `id-token: write` that runs no repository code. The build job checks that the tagged commit is on main and that a clean rebuild of the commit gives byte-identical files (`scripts/verify_dist.py`). Every action is pinned to a commit SHA.

## [0.8.0] - 2026-11-27

### 🚨 Changed

- **Breaking for services:** `django` is pinned to 6.1.3 and `djangorestframework` to 3.18.3. The pins are exact, so a service that upgrades to `shellui-django` 0.8.0 must move to Django 6.1.3 and DRF 3.18.3 in the same change, or dependency resolution fails. Django 6.1 deprecates the `EMAIL_*` settings, `get_connection`, `fail_silently` and `send_mail(connection=...)`, so services that send mail should run their tests with warnings on.

### 🐛 Bug Fixes

- MCP tool schemas keep a blank-allowed `SlugField` or `URLField` as a string. drf-spectacular 0.30 describes those fields as `oneOf` a string and an empty string, which the tool builder used to turn into a free-form JSON object.

### 🏗 Chore

- Classifiers for Django 6.1 and Python 3.15. Python 3.15 in `.python-version`. CI runs the tests on Python 3.14 and 3.15, and the package still supports Python 3.14 and later.
- ruff 0.17.6 in the lockfile.
- GitHub Actions: actions/checkout v7, astral-sh/setup-uv v10.4.0.

## [0.7.2] - 2026-11-25

### ✨ Feature

- Add `shellui_django.ui` with shared `shellui_ui/card_base.html`, `shellui_ui/error.html`, `shellui_ui/includes/favicons.html`, and `shellui_ui/includes/logo_sprite.html` templates so Shellui backend services render the same header, card, and dark-mode layout as Identity.

## [0.7.1] - 2026-11-24

### 🐛 Bug Fixes

- Telemetry no longer exports a one span trace for every database or Redis call made outside a request, task, or manual span (idle worker polls, gauge callbacks, heartbeats). The default sampler is parent based and drops those root client spans. Outbound HTTP calls and calls inside a traced operation are unchanged. `OTEL_TRACES_SAMPLER` replaces the default when set.

## [0.7.0] - 2026-11-24

### ✨ Feature

- Add `shellui_django.telemetry` behind the `[otel]` extra. `setup_telemetry()` exports traces and metrics over OTLP/HTTP and puts `trace_id` / `span_id` on log records. Nothing is imported from OpenTelemetry, and there is no runtime overhead, unless an OTLP endpoint is set and `OTEL_SDK_DISABLED` is not true.
- Instrument Django, psycopg, redis, requests, and Celery, and propagate W3C `traceparent` on outbound `requests` and into Celery tasks. Health, readiness, liveness, static, favicon, and `/metrics` URLs are excluded from traces. SQL literals, credential query parameters, request bodies, and auth or cookie headers are removed from spans.
- Add `counter()`, `histogram()`, and `set_shellui_attributes()` so services can record metrics and attach opaque company and user ids.

### 📚 Documentation

- Document enabling telemetry from WSGI, ASGI, Celery, and long-running management commands in `docs/telemetry.md`.

## [0.6.0] - 2026-11-21

Breaking: services must pass the new `McpServer` settings listed under Changed before upgrading.

### 🛠 Improvements

- MCP `tools/call` checks tenant fields (`company_id`, `companyId`, `company-id`) in tool arguments, including nested objects, against the verified token `company_id`. The aggregating gateway applies the same check before it forwards a call. `0` is a real company id.
- `McpServer.handle` verifies the bearer token (RS256, `identity_issuer`, `mcp_audience`, JWKS) and authenticates the inner view with those claims.
- `identity_revocation_check` runs on every request. A missing hook, or a hook that raises, is rejected with HTTP 403 `revocation_unavailable`.
- Identity JWKS fetch uses the configured URL only: redirects are not followed, `https` is required unless Django `DEBUG` is true, other schemes are rejected, the body is capped at 256 KiB, and the timeout must be positive (default 10 seconds).
- Internal assertion verification requires `target` to equal `expected_target`. An empty or missing `target` does not match.
- `mcp_gateway_delegated` skips a second approval only for the tool named in `action` while `exp` is still in the future.

### 🚨 Changed

- `McpServer` needs `identity_issuer`, `mcp_audience`, and `identity_jwks` or `identity_jwks_url`, plus `identity_revocation_check`. `handle` does not authorize from the `agent_claims` argument. Inner `request.user` is the verified agent principal, and `request.auth` is the verified claims.
- `mcp_gateway_delegated` must be an object `{"action": "<tool name>", "exp": <unix seconds>}`. A boolean value does not skip approval.
- JWKS clients that used plain `http` while `DEBUG` is false, or that followed a redirect, now get an error from `get_jwks_document`.

### 🏗 Chore

- PyPI publishing checks that the release tag matches the package version before upload.

## [0.5.3] - 2026-11-11

### 🐛 Bug Fixes

- MCP `tools/call`: honor `mcp_gateway_delegated` on agent tokens so downstream services do not open a second human approval after the AI company gateway already approved and consumed the grant.

## [0.5.2] - 2026-11-11

### 🐛 Bug Fixes

- MCP `tools/list`: keep registry `_meta` (path, method, read_only, destructive) on the wire. Services publish flat agent schemas without transport arguments; the AI gateway needs `_meta` to route `tools/call`. Other private `_` keys are still stripped.
- MCP argument validation: ignore DRF `format` query noise so legacy nested `tools/call` envelopes from older MCP clients do not fail with `Unexpected query fields: format`.

## [0.5.1] - 2026-11-09

### 🐛 Bug Fixes

- MCP resource indicators: allow plain `http` for private and CGNAT (RFC 6598 `100.64.0.0/10`, e.g. Tailscale) IP literals in addition to loopback. Public hostnames over `http` remain rejected.
- `tools_from_schema`: resolve OpenAPI `$ref` request bodies and emit typed `body` / `query` properties. Previously `$ref`-only bodies (common with drf-spectacular) produced an empty `body` object, so MCP clients could not submit fields such as template draft `subject` / `document`. Untyped JSONField fragments become free-form objects (`additionalProperties: true`).
- `tools_from_schema`: field schemas also resolve nested `$ref`, `allOf`, and `oneOf`/`anyOf` wrappers, so drf-spectacular choice fields stay typed strings with their `enum` values, nested serializers stay typed objects, and nullable fields accept `null`.

### 📚 Documentation

- Document private/CGNAT `http` resource URLs and `$ref` body expansion for MCP tools.

## [0.5.0] - 2026-11-06

### 🛠 Improvements

- MCP internal assertions: optional regional authority fields on `build_mcp_approval_assertion` (`grant_version`, `global_company_id`, `company_binding_version`) and optional revocation policy metadata on `build_mcp_revocation_list_response_assertion` (`revocation_policy_version`, `max_active_grant_version`); strict non-negative integers, delegated global pair rules (`is not None` only), body and JWT parity for top-level policy fields (legacy digit strings on the HTTP envelope), per-agent binding validation with `mcp_authority_snapshot_fingerprint` and `mcp_authority_snapshot_rejected` on trusted rows, delegated grant cap checks against signed `max_active_grant_version` without blocking personal rows, `jti` and lifetime invariants (`exp` after `iat`, 600 s cap) on Identity-signed revocation lists, and positive `cache_seconds` bounded by the same cap.
- Revocation list verification: strict `iat` / `exp` types after decode (reject bool and float; digit strings coerced), clock window aligned with `IDENTITY_RS256_LEEWAY_SECONDS` (5 s) on `decode_identity_rs256_jwt`.
- `decode_identity_rs256_jwt` always requires `exp`, `iat`, `sub`, `scope`, and `jti`; `require_claims` adds further required names (union). Timestamps are normalized to integers after verify.
- `verify_rs256_mcp_assertion` lifetime checks use the same strict timestamp parsing as revocation (no `int()` on raw claims).
- Destructive MCP tools always require approval in `full` mode; `mcp_destructive` does not skip the gate.

### 📚 Documentation

- `docs/mcp.md`: regional authority, revocation policy proof, per-agent binding snapshots, numeric `0` vs omitted or `None`, `decode_identity_rs256_jwt` requirements, and destructive approval rules.

## [0.4.0] - 2026-11-04

### 🔒 Security

- Service-to-identity MCP internal assertions (`build_mcp_approval_assertion`, `build_mcp_call_log_assertion`, `build_mcp_revocation_assertion`) are signed RS256 with the caller `JWT_SIGNING_KEY` and caller issuer (`JWT_ISSUER` or SimpleJWT `ISSUER`), not SimpleJWT HMAC keys.
- `verify_mcp_internal_assertion` / `verify_rs256_mcp_assertion` verify RS256 against caller JWKS or PEM (`expected_issuer`, audience, scope, target, lifetime, optional `register_jti`). HS256 and `alg: none` are rejected; verification never uses a private key.

### 🚨 Changed

- `verify_mcp_internal_assertion` now requires `public_jwks_or_pem` and `expected_issuer` (breaking for Identity and other verifiers).

## [0.3.0] - 2026-11-02

### ✨ Feature

- Add `shellui_django.mcp.delegation`: RS256 helpers for gateway-to-Identity downstream MCP token mint requests (`sign_downstream_token_request`, `verify_downstream_token_request`) with shared audience and scope constants.

### 📚 Documentation

- Document downstream token delegation in `docs/mcp.md`.

## [0.2.1] - 2026-11-02

### 📚 Documentation

- Add CI, PyPI, Python and license badges to the README.

## [0.2.0] - 2026-11-02

### ✨ Feature

- Add `shellui_django.mcp.gateway`: `AggregatingMcpServer` merges downstream `tools/list` and forwards `tools/call` with service-scoped RS256 tokens (`aud` = `{service}/mcp`). Host apps inject the service URL map, agent lookup, and token minting.

### 📚 Documentation

- Document the MCP aggregating gateway in `docs/mcp.md`.

### 🏗 Chore

- PyPI metadata: license file, classifiers, keywords and project links.

## [0.1.0] - 2026-11-02

### ✨ Feature

- First release of `shellui-django` with the shared MCP module (OpenAPI tools, write gate, revocation helpers, streamable HTTP server).

### 📚 Documentation

- Add package README and `docs/` guides for the MCP and testing modules.
