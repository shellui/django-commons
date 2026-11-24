"""Configure OpenTelemetry. Imported only when telemetry is enabled."""

from __future__ import annotations

import importlib
import logging
import os
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
from opentelemetry.util._once import Once

from shellui_django.telemetry._env import (
    blank_to_none,
    disabled_instrumentations,
    django_excluded_urls,
    endpoint_for,
    environment_resource_attributes,
    otlp_protocol,
    protocol_supported,
    wants_otlp,
)
from shellui_django.telemetry._sanitize import sanitize_attributes
from shellui_django.telemetry._state import state

logger = logging.getLogger(__name__)

_HTTP_STABILITY = 'OTEL_SEMCONV_STABILITY_OPT_IN'


class _SanitizingSpanProcessor:
    """Strip secrets from spans before they are exported.

    The SDK freezes attributes before processors run, then builds the readable
    span those processors export. Replacing the attribute mapping here is what
    the exporter observes.
    """

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        return None

    def _on_ending(self, span: Any) -> None:
        current = getattr(span, '_attributes', None)
        if not current:
            return
        try:
            original = dict(current)
            sanitized = sanitize_attributes(original)
            if sanitized != original:
                span._attributes = sanitized
        except Exception:
            logger.exception('shellui telemetry: failed to sanitize span attributes')

    def on_end(self, span: Any) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def _resource(
    service_name: str | None,
    service_version: str | None,
    environment: str | None,
    region: str | None,
) -> Resource:
    # Resource.create() lets explicit attributes override the environment.
    # Leave keys that the operator already set so OTEL_SERVICE_NAME and
    # OTEL_RESOURCE_ATTRIBUTES win.
    existing = environment_resource_attributes()
    attributes: dict[str, str] = {}
    if service_name and 'service.name' not in existing:
        attributes['service.name'] = service_name
    if service_version and 'service.version' not in existing:
        attributes['service.version'] = service_version
    chosen_environment = (
        existing.get('deployment.environment') or existing.get('deployment.environment.name') or environment
    )
    if chosen_environment and 'deployment.environment' not in existing:
        attributes['deployment.environment'] = chosen_environment
    if chosen_environment and 'deployment.environment.name' not in existing:
        attributes['deployment.environment.name'] = chosen_environment
    if region and 'cloud.region' not in existing:
        attributes['cloud.region'] = region
    return Resource.create(attributes)


def _build_span_processor(span_exporter: Any, batch_export: bool | None, meter_provider: MeterProvider) -> Any | None:
    if span_exporter is not None:
        if batch_export:
            return BatchSpanProcessor(span_exporter, meter_provider=meter_provider)
        return SimpleSpanProcessor(span_exporter, meter_provider=meter_provider)
    if not wants_otlp('TRACES'):
        return None
    if not protocol_supported('TRACES'):
        logger.error(
            'shellui telemetry supports OTLP over HTTP protobuf only. Traces protocol %s is not supported.',
            otlp_protocol('TRACES'),
        )
        return None
    if not endpoint_for('TRACES'):
        return None
    return BatchSpanProcessor(OTLPSpanExporter(), meter_provider=meter_provider)


def _build_metric_reader(metric_reader: Any) -> Any | None:
    if metric_reader is not None:
        return metric_reader
    if not wants_otlp('METRICS'):
        return None
    if not protocol_supported('METRICS'):
        logger.error(
            'shellui telemetry supports OTLP over HTTP protobuf only. Metrics protocol %s is not supported.',
            otlp_protocol('METRICS'),
        )
        return None
    if not endpoint_for('METRICS'):
        return None
    return PeriodicExportingMetricReader(OTLPMetricExporter())


def _apply(name: str, instrumentor: Any, **kwargs: Any) -> None:
    if name in disabled_instrumentations():
        logger.info(
            'shellui telemetry: %s instrumentation disabled by OTEL_PYTHON_DISABLED_INSTRUMENTATIONS',
            name,
        )
        return
    if instrumentor.is_instrumented_by_opentelemetry:
        state.instrumentors.append(instrumentor)
        return
    instrumentor.instrument(**kwargs)
    if instrumentor.is_instrumented_by_opentelemetry:
        state.instrumentors.append(instrumentor)
        return
    logger.warning('shellui telemetry: %s instrumentation was not applied', name)


def _import_instrumentor(module: str, class_name: str) -> Any | None:
    try:
        imported = importlib.import_module(module)
    except ImportError:
        logger.warning('shellui telemetry: %s is not installed', module)
        return None
    return getattr(imported, class_name)()


def _instrument_django(tracer_provider: TracerProvider, meter_provider: MeterProvider) -> None:
    if not os.environ.get('DJANGO_SETTINGS_MODULE'):
        logger.info('shellui telemetry: DJANGO_SETTINGS_MODULE is unset, skipping Django instrumentation')
        return
    from django.conf import settings

    try:
        # Load the service settings. DjangoInstrumentor calls settings.configure()
        # when they are not loaded yet, which then blocks the real settings module.
        middleware = settings.MIDDLEWARE
    except Exception:
        logger.warning('shellui telemetry: Django settings are not configured, skipping Django instrumentation')
        return
    if not isinstance(middleware, (list, tuple)):
        logger.warning('shellui telemetry: Django MIDDLEWARE is not a list, skipping Django instrumentation')
        return
    instrumentor = _import_instrumentor('opentelemetry.instrumentation.django', 'DjangoInstrumentor')
    if instrumentor is None:
        return
    _apply(
        'django',
        instrumentor,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        excluded_urls=django_excluded_urls(),
    )


def _instrument_library(
    name: str,
    module: str,
    class_name: str,
    *,
    tracer_provider: TracerProvider,
    meter_provider: MeterProvider | None = None,
    **kwargs: Any,
) -> None:
    instrumentor = _import_instrumentor(module, class_name)
    if instrumentor is None:
        return
    options = {'tracer_provider': tracer_provider, **kwargs}
    if meter_provider is not None:
        options['meter_provider'] = meter_provider
    _apply(name, instrumentor, **options)


def _install_log_correlation(tracer_provider: TracerProvider, service_name: str) -> None:
    state.previous_log_factory = logging.getLogRecordFactory()
    instrumentor = _import_instrumentor('opentelemetry.instrumentation.logging', 'LoggingInstrumentor')
    if instrumentor is not None:
        _apply(
            'logging',
            instrumentor,
            tracer_provider=tracer_provider,
            set_logging_format=False,
            inject_trace_context=True,
            enable_log_auto_instrumentation=False,
        )
    previous = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        trace_id = getattr(record, 'otelTraceID', None)
        span_id = getattr(record, 'otelSpanID', None)
        if trace_id is None or span_id is None:
            current = trace.get_current_span()
            context = current.get_span_context()
            if context is not None and context.is_valid:
                record.otelTraceID = format(context.trace_id, '032x')
                record.otelSpanID = format(context.span_id, '016x')
                record.otelTraceSampled = bool(context.trace_flags.sampled)
            else:
                record.otelTraceID = '0'
                record.otelSpanID = '0'
                record.otelTraceSampled = False
            if not getattr(record, 'otelServiceName', None):
                record.otelServiceName = service_name
        record.trace_id = record.otelTraceID
        record.span_id = record.otelSpanID
        return record

    logging.setLogRecordFactory(factory)


def _configure_process(
    service_name: str | None,
    service_version: str | None,
    environment: str | None,
    region: str | None,
    span_exporter: Any,
    metric_reader: Any,
    batch_export: bool | None,
) -> bool:
    # Stable HTTP metrics (http.server.request.duration) unless the operator chose otherwise.
    os.environ.setdefault(_HTTP_STABILITY, 'http')

    resource = _resource(service_name, service_version, environment, region)
    resolved_name = str(resource.attributes.get('service.name', service_name or ''))
    reader = _build_metric_reader(metric_reader)
    readers = [reader] if reader is not None else []
    meter_provider = MeterProvider(resource=resource, metric_readers=readers)
    processor = _build_span_processor(span_exporter, batch_export, meter_provider)
    if processor is None and reader is None:
        meter_provider.shutdown()
        logger.error(
            'shellui telemetry: no OTLP exporter was configured. The supported protocol is http/protobuf.',
        )
        return False

    metrics.set_meter_provider(meter_provider)
    tracer_provider = TracerProvider(resource=resource, meter_provider=meter_provider)
    tracer_provider.add_span_processor(_SanitizingSpanProcessor())
    if processor is not None:
        tracer_provider.add_span_processor(processor)
    trace.set_tracer_provider(tracer_provider)

    state.tracer_provider = tracer_provider
    state.meter_provider = meter_provider
    state.service_name = resolved_name
    # Mark active before instrumentation so instrumentors observe a live SDK,
    # and so a failure below can still be torn down.
    state.active = True
    state.pid = os.getpid()

    _instrument_django(tracer_provider, meter_provider)
    _instrument_library(
        'psycopg',
        'opentelemetry.instrumentation.psycopg',
        'PsycopgInstrumentor',
        tracer_provider=tracer_provider,
        capture_parameters=False,
        enable_commenter=False,
    )
    _instrument_library(
        'redis',
        'opentelemetry.instrumentation.redis',
        'RedisInstrumentor',
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
    )
    _instrument_library(
        'requests',
        'opentelemetry.instrumentation.requests',
        'RequestsInstrumentor',
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
    )
    _instrument_library(
        'celery',
        'opentelemetry.instrumentation.celery',
        'CeleryInstrumentor',
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
    )
    _install_log_correlation(tracer_provider, resolved_name)
    state.generation += 1
    return True


def configure(
    service_name: str | None,
    *,
    service_version: str | None,
    environment: str | None,
    region: str | None,
    span_exporter: Any,
    metric_reader: Any,
    batch_export: bool | None,
) -> bool:
    if state.active and state.pid == os.getpid():
        return True
    if state.active and state.pid is not None and state.pid != os.getpid():
        # Gunicorn preload and Celery prefork copy this state into the child.
        # The SDK restarts batch exporter threads after fork, so a second setup
        # call must not replace the global providers.
        state.pid = os.getpid()
        return True

    service_name = blank_to_none(service_name)
    if service_name is None and 'service.name' not in environment_resource_attributes():
        logger.error('shellui telemetry: pass service_name or set OTEL_SERVICE_NAME')
        return False

    try:
        return _configure_process(
            service_name,
            blank_to_none(service_version),
            blank_to_none(environment),
            blank_to_none(region),
            span_exporter,
            metric_reader,
            batch_export,
        )
    except Exception:
        logger.exception('shellui telemetry: setup failed')
        reset_for_tests()
        return False


def shutdown() -> None:
    provider = state.tracer_provider
    meter_provider = state.meter_provider
    state.active = False
    if provider is not None:
        provider.shutdown()
    if meter_provider is not None:
        meter_provider.shutdown()


def _restore_log_factory() -> None:
    previous = state.previous_log_factory
    if previous is not None:
        logging.setLogRecordFactory(previous)


def _clear_global_providers() -> None:
    trace._TRACER_PROVIDER_SET_ONCE = Once()
    trace._TRACER_PROVIDER = None
    metrics_internal = importlib.import_module('opentelemetry.metrics._internal')
    metrics_internal._METER_PROVIDER_SET_ONCE = Once()
    metrics_internal._METER_PROVIDER = None


def reset_for_tests() -> None:
    """Uninstrument, drop providers, and allow setup to run again. Test-only."""
    for instrumentor in reversed(state.instrumentors):
        try:
            instrumentor.uninstrument()
        except Exception:
            logger.exception('shellui telemetry: failed to uninstrument %s', type(instrumentor).__name__)
    state.instrumentors = []
    _restore_log_factory()
    tracer_provider = state.tracer_provider
    meter_provider = state.meter_provider
    state.tracer_provider = None
    state.meter_provider = None
    state.active = False
    if tracer_provider is not None:
        try:
            tracer_provider.shutdown()
        except Exception:
            logger.exception('shellui telemetry: tracer provider shutdown failed')
    if meter_provider is not None:
        try:
            meter_provider.shutdown()
        except Exception:
            logger.exception('shellui telemetry: meter provider shutdown failed')
    try:
        _clear_global_providers()
    except Exception:
        logger.exception('shellui telemetry: failed to clear global providers')
    state.clear()
