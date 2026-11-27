# shellui-django

[![CI](https://github.com/shellui/django-commons/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shellui/django-commons/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/shellui-django)](https://pypi.org/project/shellui-django/)
[![Python](https://img.shields.io/pypi/pyversions/shellui-django)](https://pypi.org/project/shellui-django/)
[![License: MIT](https://img.shields.io/github/license/shellui/django-commons)](LICENSE)

Shared Django libraries for [Shellui](https://shellui.com) backend services: identity, email, storage, hosting, saas, ai, and marketplace.

## Principles

- Only code duplicated in two or more services belongs here.
- Optional modules. Install what you need via extras (for example `[mcp]`).
- No shared Django models or migrations for now.
- [Semantic versioning](https://semver.org/). Services pin a compatible version range.

## Install

```bash
pip install shellui-django
pip install shellui-django[mcp]    # MCP server helpers
pip install shellui-django[otel]   # OpenTelemetry traces, metrics, and log correlation
```

Requires Python 3.14+ (tested on 3.15), Django, and DRF. The `[mcp]` extra adds PyJWT, cryptography, SimpleJWT, and requests for MCP auth, signed internal calls, and the aggregating gateway. The `[otel]` extra adds the OpenTelemetry SDK, the OTLP/HTTP exporter, and instrumentation for Django, psycopg, redis, requests, Celery, and logging. See [docs/telemetry.md](docs/telemetry.md).

## Modules

| Module | Description |
|--------|-------------|
| [`shellui_django.mcp`](docs/mcp.md) | Turn a DRF OpenAPI schema into a secure multi-tenant MCP HTTP server. |
| [`shellui_django.telemetry`](docs/telemetry.md) | Traces, metrics, and log correlation for Shellui services. |
| `shellui_django.ui` | Shared card and error templates matching Shellui Identity. |
| [`shellui_django.testing`](docs/testing.md) | Shared test helpers (planned). |

## Contributing and releases

1. Open pull requests against `develop`.
2. Merge `develop` into `main` when ready to release.
3. Tag `vX.Y.Z` on `main`. GitHub Actions publishes `shellui-django` to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/).

Run checks locally:

```bash
uv sync --all-groups
uv run pytest
uv run ruff check src
uv build
```

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md). Do not open public issues for undisclosed security problems.

## License

MIT. See [LICENSE](LICENSE).
