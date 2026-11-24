import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
import requests
from celery import Celery
from django.conf import settings
from django.test import Client, override_settings
from opentelemetry import trace
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

from shellui_django.telemetry import (
    TraceContextFormatter,
    _reset_for_tests,
    canonical_metric_name,
    counter,
    histogram,
    set_shellui_attributes,
    setup_telemetry,
    telemetry_enabled,
)
from shellui_django.telemetry._state import state

_CLEARED_ENV = (
    'OTEL_EXPORTER_OTLP_ENDPOINT',
    'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT',
    'OTEL_EXPORTER_OTLP_METRICS_ENDPOINT',
    'OTEL_EXPORTER_OTLP_PROTOCOL',
    'OTEL_EXPORTER_OTLP_TRACES_PROTOCOL',
    'OTEL_EXPORTER_OTLP_METRICS_PROTOCOL',
    'OTEL_SDK_DISABLED',
    'OTEL_TRACES_EXPORTER',
    'OTEL_METRICS_EXPORTER',
    'OTEL_SERVICE_NAME',
    'OTEL_RESOURCE_ATTRIBUTES',
)


def _exporters():
    return InMemorySpanExporter(), InMemoryMetricReader()


def _enable(monkeypatch, **kwargs):
    for key in _CLEARED_ENV:
        monkeypatch.delenv(key, raising=False)
    span_exporter, metric_reader = _exporters()
    assert setup_telemetry(
        'shellui-identity',
        service_version='1.2.3',
        environment='test',
        region='eu',
        span_exporter=span_exporter,
        metric_reader=metric_reader,
        **kwargs,
    )
    return span_exporter, metric_reader


def _metric_points(data, name):
    if data is None:
        return []
    points = []
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                if metric.name == name:
                    points.extend(metric.data.data_points)
    return points


def test_canonical_metric_names():
    assert canonical_metric_name('email_sent_total') == 'email.sent'
    assert canonical_metric_name('HTTP_Requests_Total') == 'http.requests'
    assert canonical_metric_name('http.server.request.duration') == 'http.server.request.duration'
    with pytest.raises(ValueError):
        canonical_metric_name('1bad')


def test_disabled_without_endpoint(monkeypatch):
    for key in _CLEARED_ENV:
        monkeypatch.delenv(key, raising=False)
    assert telemetry_enabled() is False
    assert setup_telemetry('shellui-identity') is False
    assert state.active is False


def test_sdk_disabled_overrides_endpoint_and_exporter(monkeypatch):
    monkeypatch.setenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://127.0.0.1:4318')
    monkeypatch.setenv('OTEL_SDK_DISABLED', 'true')
    assert telemetry_enabled() is False
    assert setup_telemetry('shellui-identity', span_exporter=InMemorySpanExporter()) is False


def test_grpc_protocol_is_rejected(monkeypatch):
    monkeypatch.setenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://127.0.0.1:4318')
    monkeypatch.setenv('OTEL_EXPORTER_OTLP_PROTOCOL', 'grpc')
    assert setup_telemetry('shellui-identity') is False
    assert state.active is False


def test_resource_defaults_and_environment_override(monkeypatch):
    _span_exporter, _reader = _enable(monkeypatch)
    resource = trace.get_tracer_provider().resource.attributes
    assert resource['service.name'] == 'shellui-identity'
    assert resource['service.version'] == '1.2.3'
    assert resource['deployment.environment'] == 'test'
    assert resource['deployment.environment.name'] == 'test'
    assert resource['cloud.region'] == 'eu'

    _reset_for_tests()
    monkeypatch.setenv('OTEL_SERVICE_NAME', 'from-env')
    monkeypatch.setenv(
        'OTEL_RESOURCE_ATTRIBUTES',
        'deployment.environment=production,service.version=9.9.9,cloud.region=us',
    )
    assert setup_telemetry(
        'from-code',
        service_version='1.0.0',
        environment='local',
        region='eu',
        span_exporter=InMemorySpanExporter(),
        metric_reader=InMemoryMetricReader(),
    )
    resource = trace.get_tracer_provider().resource.attributes
    assert resource['service.name'] == 'from-env'
    assert resource['service.version'] == '9.9.9'
    assert resource['deployment.environment'] == 'production'
    assert resource['deployment.environment.name'] == 'production'
    assert resource['cloud.region'] == 'us'


def test_sampler_env_is_honored(monkeypatch):
    monkeypatch.setenv('OTEL_TRACES_SAMPLER', 'always_off')
    span_exporter, _reader = _enable(monkeypatch)
    tracer = trace.get_tracer('shellui.test')
    with tracer.start_as_current_span('dropped'):
        pass
    assert span_exporter.get_finished_spans() == ()


def test_orphan_client_spans_are_dropped(monkeypatch):
    monkeypatch.delenv('OTEL_TRACES_SAMPLER', raising=False)
    span_exporter, _reader = _enable(monkeypatch)
    tracer = trace.get_tracer('shellui.test')
    with tracer.start_as_current_span('SELECT', kind=SpanKind.CLIENT):
        pass
    with tracer.start_as_current_span('GET', kind=SpanKind.CLIENT, attributes={'http.request.method': 'GET'}):
        pass
    with tracer.start_as_current_span('task', kind=SpanKind.CONSUMER):
        with tracer.start_as_current_span('UPDATE', kind=SpanKind.CLIENT):
            pass
    assert sorted(span.name for span in span_exporter.get_finished_spans()) == ['GET', 'UPDATE', 'task']


def test_sampler_env_keeps_orphan_client_spans(monkeypatch):
    monkeypatch.setenv('OTEL_TRACES_SAMPLER', 'parentbased_always_on')
    span_exporter, _reader = _enable(monkeypatch)
    with trace.get_tracer('shellui.test').start_as_current_span('SELECT', kind=SpanKind.CLIENT):
        pass
    assert [span.name for span in span_exporter.get_finished_spans()] == ['SELECT']


def test_sql_headers_and_query_are_redacted_on_export(monkeypatch):
    span_exporter, _reader = _enable(monkeypatch)
    tracer = trace.get_tracer('shellui.test')
    with tracer.start_as_current_span('query') as span:
        span.set_attribute('db.statement', "SELECT * FROM users WHERE email = 'ada@example.com' AND id = 42")
        span.set_attribute('http.request.header.authorization', ('Bearer secret',))
        span.set_attribute('url.full', 'https://identity.internal/v1/me?token=abc&page=2')
    finished = span_exporter.get_finished_spans()
    attributes = dict(finished[-1].attributes)
    assert 'ada@example.com' not in attributes['db.statement']
    assert '42' not in attributes['db.statement']
    assert 'http.request.header.authorization' not in attributes
    assert 'abc' not in attributes['url.full']
    assert 'page=2' in attributes['url.full']


def test_shellui_attributes_keep_opaque_ids_only(monkeypatch, caplog):
    span_exporter, _reader = _enable(monkeypatch)
    tracer = trace.get_tracer('shellui.test')
    with tracer.start_as_current_span('request'):
        set_shellui_attributes(
            company_id=0,
            user_id='01HXYZ',
            attributes={'agent_id': 'agt_1', 'email': 'ada@example.com', 'note': 'Ada Lovelace'},
        )
        set_shellui_attributes(user_id='ada@example.com')
    attributes = dict(span_exporter.get_finished_spans()[-1].attributes)
    assert attributes['shellui.company_id'] == '0'
    assert attributes['shellui.user_id'] == '01HXYZ'
    assert attributes['shellui.agent_id'] == 'agt_1'
    assert 'shellui.email' not in attributes
    assert 'shellui.note' not in attributes
    assert 'ada@example.com' not in caplog.text


def test_log_records_carry_trace_ids(monkeypatch):
    _enable(monkeypatch)
    tracer = trace.get_tracer('shellui.test')
    captured: list[logging.LogRecord] = []

    class _Handler(logging.Handler):
        def emit(self, record):
            captured.append(record)

    log = logging.getLogger('shellui.telemetry.test')
    handler = _Handler()
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        with tracer.start_as_current_span('request') as span:
            log.info('hello')
            context = span.get_span_context()
        record = captured[-1]
        assert record.trace_id == format(context.trace_id, '032x')
        assert record.span_id == format(context.span_id, '016x')
        assert record.otelTraceID == record.trace_id
        assert record.otelSpanID == record.span_id
        assert record.otelServiceName == 'shellui-identity'
        formatted = TraceContextFormatter('%(trace_id)s %(span_id)s %(message)s').format(record)
        assert record.trace_id in formatted
    finally:
        log.removeHandler(handler)


def test_formatter_defaults_when_telemetry_is_off():
    record = logging.LogRecord('shellui', logging.INFO, __file__, 1, 'hello', (), None)
    formatted = TraceContextFormatter('trace_id=%(trace_id)s span_id=%(span_id)s %(message)s').format(record)
    assert formatted == 'trace_id=0 span_id=0 hello'


def test_metrics_helpers_bind_after_setup(monkeypatch):
    sent = counter('email_sent_total', description='Emails accepted')
    duration = histogram('email_send_seconds', unit='s', description='Send latency')
    sent.add(1)
    _span_exporter, reader = _enable(monkeypatch)
    sent.add(4, {'company_id': '12'})
    duration.record(0.25, {'company_id': '12'})
    data = reader.get_metrics_data()
    counter_points = _metric_points(data, 'email.sent')
    histogram_points = _metric_points(data, 'email.send.seconds')
    assert counter_points
    assert sum(point.value for point in counter_points) == 4
    assert histogram_points
    assert histogram_points[0].count == 1


@override_settings(
    ROOT_URLCONF='shellui_django.telemetry.tests.urls',
    MIDDLEWARE=[],
    ALLOWED_HOSTS=['testserver'],
)
def test_django_traces_metrics_and_exclusions(monkeypatch):
    monkeypatch.setenv('OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST', '.*')
    span_exporter, reader = _enable(monkeypatch)
    client = Client()

    assert client.get('/health').status_code == 200
    assert client.get('/ready').status_code == 200
    assert client.get('/live').status_code == 200
    assert client.get('/metrics').status_code == 200
    assert client.get('/static/app.js').status_code == 200
    assert client.get('/favicon.ico').status_code == 200
    assert span_exporter.get_finished_spans() == ()

    response = client.get(
        '/widgets?token=supersecret&page=2',
        HTTP_AUTHORIZATION='Bearer supersecret',
        # Gunicorn sets this. The Django test client does not, and the
        # instrumentation only records the query from REQUEST_URI or RAW_URI.
        REQUEST_URI='/widgets?token=supersecret&page=2',
    )
    assert response.status_code == 200
    spans = span_exporter.get_finished_spans()
    assert spans
    attributes = dict(spans[-1].attributes)
    blob = str(attributes)
    assert 'supersecret' not in blob
    assert attributes.get('url.query') == 'token=REDACTED&page=2'
    assert 'http.request.header.authorization' not in attributes

    healthcare = client.get('/healthcare')
    assert healthcare.status_code == 200
    assert any((span.attributes or {}).get('http.route') == 'healthcare' for span in span_exporter.get_finished_spans())

    names = []
    data = reader.get_metrics_data()
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            names.extend(metric.name for metric in scope_metric.metrics)
    assert 'http.server.request.duration' in names
    assert 'http.server.active_requests' in names

    assert setup_telemetry('shellui-identity') is True
    otel_middleware = [item for item in settings.MIDDLEWARE if 'opentelemetry' in item]
    assert len(otel_middleware) == 1


def test_requests_propagates_traceparent_and_redacts_urls(monkeypatch):
    monkeypatch.setenv('OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST', '.*')

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.captured = {key.lower(): value for key, value in self.headers.items()}
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format, *_args):
            return None

    server = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    server.captured = {}
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        span_exporter, _reader = _enable(monkeypatch)
        port = server.server_address[1]
        tracer = trace.get_tracer('shellui.test')
        with tracer.start_as_current_span('outbound') as span:
            parent = span.get_span_context()
            requests.get(
                f'http://127.0.0.1:{port}/v1/me?token=supersecret&page=2',
                headers={'Authorization': 'Bearer supersecret'},
                timeout=5,
            )
        header = server.captured['traceparent']
        assert header.split('-')[1] == format(parent.trace_id, '032x')
        client_spans = [span for span in span_exporter.get_finished_spans() if span.context.span_id != parent.span_id]
        assert client_spans
        blob = str(dict(client_spans[-1].attributes or {}))
        assert 'supersecret' not in blob
        assert 'page=2' in blob
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_celery_propagates_the_request_trace(monkeypatch):
    _enable(monkeypatch)
    app = Celery('shellui-telemetry-test')
    app.conf.update(task_always_eager=True, task_eager_propagates=True, broker_url='memory://')

    @app.task(name='shellui.telemetry.tests.add')
    def add(left, right):
        context = trace.get_current_span().get_span_context()
        return format(context.trace_id, '032x')

    tracer = trace.get_tracer('shellui.test')
    with tracer.start_as_current_span('request') as span:
        parent = format(span.get_span_context().trace_id, '032x')
        result = add.delay(1, 2)
    assert result.get(timeout=5) == parent


def test_database_and_redis_instrumentors_are_active(monkeypatch):
    _enable(monkeypatch)
    from opentelemetry.instrumentation.celery import CeleryInstrumentor
    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor

    assert PsycopgInstrumentor().is_instrumented_by_opentelemetry
    assert RedisInstrumentor().is_instrumented_by_opentelemetry
    assert RequestsInstrumentor().is_instrumented_by_opentelemetry
    assert CeleryInstrumentor().is_instrumented_by_opentelemetry
