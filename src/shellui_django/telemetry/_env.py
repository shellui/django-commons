"""Read standard OpenTelemetry environment variables. No OpenTelemetry imports."""

from __future__ import annotations

import os
from urllib.parse import unquote

# Matched against the absolute request URL (scheme, host, path, and a trailing
# '?'). Patterns are comma-separated regexes, the same shape as
# OTEL_PYTHON_DJANGO_EXCLUDED_URLS.
_HEALTH_PATHS = 'health|healthz|ready|readiness|readyz|live|livez'
DEFAULT_EXCLUDED_URLS = ','.join(
    [
        rf'/(?:{_HEALTH_PATHS})(?:/|[?]|$)',
        r'/static/',
        r'/favicon\.ico(?:[?]|$)',
        r'/metrics(?:/|[?]|$)',
    ]
)

_ENDPOINT_VARIABLES = (
    'OTEL_EXPORTER_OTLP_ENDPOINT',
    'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT',
    'OTEL_EXPORTER_OTLP_METRICS_ENDPOINT',
)

_SUPPORTED_PROTOCOLS = frozenset({'http/protobuf'})


def sdk_disabled() -> bool:
    """Return True when OTEL_SDK_DISABLED is the string true."""
    return os.environ.get('OTEL_SDK_DISABLED', '').strip().lower() == 'true'


def endpoint_configured() -> bool:
    return any(os.environ.get(name, '').strip() for name in _ENDPOINT_VARIABLES)


def signal_exporters(signal: str) -> list[str]:
    """Return exporter names for traces or metrics. Default is otlp."""
    raw = os.environ.get(f'OTEL_{signal.upper()}_EXPORTER', 'otlp')
    return [part.strip().lower() for part in raw.split(',') if part.strip()]


def signal_enabled(signal: str) -> bool:
    names = signal_exporters(signal)
    return any(name != 'none' for name in names)


def telemetry_enabled() -> bool:
    """Return True when the process should export OTLP telemetry.

    This checks environment variables only. It does not import OpenTelemetry
    and does not mean :func:`setup_telemetry` has already run.
    """
    if sdk_disabled():
        return False
    if not endpoint_configured():
        return False
    return signal_enabled('traces') or signal_enabled('metrics')


def otlp_protocol(signal: str) -> str:
    specific = os.environ.get(f'OTEL_EXPORTER_OTLP_{signal}_PROTOCOL', '').strip().lower()
    general = os.environ.get('OTEL_EXPORTER_OTLP_PROTOCOL', '').strip().lower()
    return specific or general or 'http/protobuf'


def protocol_supported(signal: str) -> bool:
    return otlp_protocol(signal) in _SUPPORTED_PROTOCOLS


def endpoint_for(signal: str) -> str:
    """Return the base or signal-specific OTLP endpoint, or an empty string."""
    specific = os.environ.get(f'OTEL_EXPORTER_OTLP_{signal}_ENDPOINT', '').strip()
    if specific:
        return specific
    return os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT', '').strip()


def wants_otlp(signal: str) -> bool:
    if not signal_enabled(signal):
        return False
    if 'otlp' not in signal_exporters(signal):
        return False
    return bool(endpoint_for(signal))


def disabled_instrumentations() -> set[str]:
    raw = os.environ.get('OTEL_PYTHON_DISABLED_INSTRUMENTATIONS', '')
    return {part.strip().lower() for part in raw.split(',') if part.strip()}


def django_excluded_urls() -> str:
    """Exclusion regexes for Django. Environment overrides win over the defaults."""
    if 'OTEL_PYTHON_DJANGO_EXCLUDED_URLS' in os.environ:
        return os.environ['OTEL_PYTHON_DJANGO_EXCLUDED_URLS']
    if 'OTEL_PYTHON_EXCLUDED_URLS' in os.environ:
        return os.environ['OTEL_PYTHON_EXCLUDED_URLS']
    return DEFAULT_EXCLUDED_URLS


def environment_resource_attributes() -> dict[str, str]:
    """Parse OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME."""
    attributes: dict[str, str] = {}
    raw = os.environ.get('OTEL_RESOURCE_ATTRIBUTES', '')
    for item in raw.split(','):
        if not item.strip() or '=' not in item:
            continue
        key, value = item.split('=', 1)
        key = key.strip()
        if key:
            attributes[key] = unquote(value.strip())
    service_name = os.environ.get('OTEL_SERVICE_NAME', '').strip()
    if service_name:
        attributes['service.name'] = service_name
    return attributes


def blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
