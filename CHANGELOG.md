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

## [0.4.1] - 2026-11-06

### 🛠 Improvements

- MCP internal assertions: optional regional authority fields on `build_mcp_approval_assertion` (`grant_version`, `global_company_id`, `company_binding_version`) and optional revocation policy metadata on `build_mcp_revocation_list_response_assertion` (`revocation_policy_version`, `max_active_grant_version`); strict non-negative integers, delegated global pair rules (`is not None` only), body and JWT parity for top-level policy fields (legacy digit strings on the HTTP envelope), per-agent binding validation with `mcp_authority_snapshot_fingerprint` and `mcp_authority_snapshot_rejected` on trusted rows, delegated grant cap checks against signed `max_active_grant_version` without blocking personal rows, `jti` and lifetime invariants (`exp` after `iat`, 600 s cap) on Identity-signed revocation lists, and positive `cache_seconds` bounded by the same cap.
- Revocation list verification: strict `iat` / `exp` types after decode (reject bool and float; digit strings coerced), clock window aligned with `IDENTITY_RS256_LEEWAY_SECONDS` (5 s) on `decode_identity_rs256_jwt`.
- `decode_identity_rs256_jwt` merges `require_claims` with mandatory `exp`, `iat`, `sub`, and `scope`.
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
