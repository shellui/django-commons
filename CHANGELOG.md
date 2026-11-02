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
