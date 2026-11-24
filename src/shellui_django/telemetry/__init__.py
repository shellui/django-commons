"""OpenTelemetry setup for Shellui Django services.

Importing this module does not import OpenTelemetry. :func:`setup_telemetry`
loads the SDK only when an OTLP endpoint is configured, ``OTEL_SDK_DISABLED``
is not true, or a caller passes an exporter for tests.
"""

from __future__ import annotations

import logging
from typing import Any

from shellui_django.telemetry._attributes import set_shellui_attributes
from shellui_django.telemetry._env import sdk_disabled, telemetry_enabled
from shellui_django.telemetry._logging import TraceContextFormatter
from shellui_django.telemetry._metrics import canonical_metric_name, counter, get_meter, histogram
from shellui_django.telemetry._state import state

logger = logging.getLogger(__name__)

__all__ = [
    'TraceContextFormatter',
    'canonical_metric_name',
    'counter',
    'get_meter',
    'histogram',
    'set_shellui_attributes',
    'setup_telemetry',
    'shutdown_telemetry',
    'telemetry_enabled',
]


def setup_telemetry(
    service_name: str,
    *,
    service_version: str | None = None,
    environment: str | None = None,
    region: str | None = None,
    span_exporter: Any = None,
    metric_reader: Any = None,
    batch_export: bool | None = None,
) -> bool:
    """Enable traces, metrics, and log correlation. Return True when active.

    Call this once, early, from the WSGI or ASGI entrypoint, from the Celery
    app module, and from management commands that run a long worker. Gunicorn
    ``preload_app`` and Celery prefork are safe: the SDK restarts exporter
    threads in the child, and a later call in that child does not build a
    second provider.

    The call does nothing unless ``OTEL_EXPORTER_OTLP_ENDPOINT`` (or a
    signal-specific endpoint) is set, or an exporter is passed. ``OTEL_SDK_DISABLED=true``
    always leaves telemetry off. ``OTEL_SERVICE_NAME`` overrides ``service_name``.
    ``OTEL_RESOURCE_ATTRIBUTES`` overrides ``environment``, ``service_version``,
    and ``region``.

    ``span_exporter`` and ``metric_reader`` are for tests and custom backends.
    A custom span exporter is flushed on every span unless ``batch_export`` is
    true. OTLP uses a batch processor. The protocol is ``http/protobuf``.
    """
    if sdk_disabled():
        return False
    custom = span_exporter is not None or metric_reader is not None
    # A second call in this process (or a forked child) must not require the
    # endpoint check again. The first call is the one that decides.
    if not state.active and not telemetry_enabled() and not custom:
        return False
    try:
        from shellui_django.telemetry._setup import configure
    except ImportError:
        logger.error(
            'shellui telemetry is enabled but the otel extra is not installed. '
            'Install shellui-django[otel].'
        )
        return False
    return configure(
        service_name,
        service_version=service_version,
        environment=environment,
        region=region,
        span_exporter=span_exporter,
        metric_reader=metric_reader,
        batch_export=batch_export,
    )


def shutdown_telemetry() -> None:
    """Flush and shut down providers. No effect when telemetry is off."""
    if not state.active:
        return
    from shellui_django.telemetry._setup import shutdown

    shutdown()


def _reset_for_tests() -> None:
    """Drop SDK state so tests can call :func:`setup_telemetry` again."""
    try:
        from shellui_django.telemetry._setup import reset_for_tests
    except ImportError:
        state.clear()
        return
    reset_for_tests()
