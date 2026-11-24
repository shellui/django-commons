# OpenTelemetry (`shellui_django.telemetry`)

Shared traces, metrics, and log correlation for Shellui Django services. One request can be followed from the service that accepted it, through `requests` calls such as the MCP gateway, and into Celery tasks.

Install the extra:

```bash
pip install shellui-django[otel]
```

The module is inert until you call `setup_telemetry` and an OTLP endpoint is configured. Importing `shellui_django` or `shellui_django.telemetry` does not import OpenTelemetry.

## Enable

Call `setup_telemetry` once, as early as possible, after `DJANGO_SETTINGS_MODULE` is set and before the process serves traffic or consumes tasks. Use the same call in the WSGI app, the ASGI app, the Celery app module, and management commands that run a long worker (for example `manage.py run_email_worker`).

```python
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'identity.settings')

from shellui_django.telemetry import setup_telemetry

setup_telemetry(
    service_name='shellui-identity',
    service_version=os.environ.get('SHELLUI_VERSION'),
    environment=os.environ.get('SHELLUI_ENVIRONMENT'),
    region=os.environ.get('SHELLUI_REGION'),
)

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
```

ASGI is the same, with `django.core.asgi.get_asgi_application`. Gunicorn `gthread` workers and `preload_app` are safe: the SDK restarts its export threads after fork. Celery prefork is the same. Do not wrap the process with `opentelemetry-instrument`.

`service_name` should be the Shellui service (`shellui-identity`, `shellui-email`, `shellui-storage`, `shellui-hosting`, `shellui-saas`, `shellui-ai`, `shellui-marketplace`). `OTEL_SERVICE_NAME` overrides the argument. `environment` is stored as `deployment.environment` and `deployment.environment.name`. `region` is stored as `cloud.region`. Values already present in `OTEL_RESOURCE_ATTRIBUTES` win.

## Environment

Production talks to SigNoz over OTLP/HTTP with protobuf and basic auth. Local Jaeger can use the same variables later.

```bash
OTEL_SERVICE_NAME=shellui-identity
OTEL_EXPORTER_OTLP_ENDPOINT=https://signoz.example:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic%20<base64 of user:password>
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production,service.version=1.2.3,cloud.region=eu
OTEL_TRACES_SAMPLER=parentbased_traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1
```

| Variable | Role |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Turns telemetry on. Signal-specific `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` also count. |
| `OTEL_SDK_DISABLED=true` | Leaves telemetry off even if an endpoint is set. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` only. `grpc` and `http/json` are rejected. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Exporter headers, including SigNoz basic auth. Also read per signal. |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Export timeout, seconds. |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | `none`, `gzip`, or `deflate`. |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | CA bundle for TLS. Client cert and key use the standard `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE` and `OTEL_EXPORTER_OTLP_CLIENT_KEY`. |
| `OTEL_SERVICE_NAME` | Overrides the `service_name` argument. |
| `OTEL_RESOURCE_ATTRIBUTES` | Overrides `service.version`, `deployment.environment`, and `cloud.region` when those keys are present. |
| `OTEL_TRACES_SAMPLER` | Unset by default: parent based, and database or Redis calls with no parent span are dropped (see below). Setting it replaces that default with a standard SDK sampler: `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio`. |
| `OTEL_TRACES_SAMPLER_ARG` | Sampling ratio in `[0, 1]` for the ratio samplers. |
| `OTEL_TRACES_EXPORTER` / `OTEL_METRICS_EXPORTER` | `otlp` (default) or `none`. |
| `OTEL_METRIC_EXPORT_INTERVAL` | Milliseconds between metric exports. Default 60000. |
| `OTEL_BSP_SCHEDULE_DELAY` | Batch span delay, plus the other standard `OTEL_BSP_*` queue settings. |
| `OTEL_PROPAGATORS` | Leave unset. The SDK default is W3C `tracecontext` and `baggage`, which is what service-to-service `requests` calls send as `traceparent`. |
| `OTEL_SEMCONV_STABILITY_OPT_IN` | Defaults to `http` so HTTP spans and the `http.server.request.duration` metric use the stable semantic conventions. Set this yourself to override, for example `http/dup`. |
| `OTEL_PYTHON_DJANGO_EXCLUDED_URLS` | Comma-separated regexes that replace the default exclusions. `OTEL_PYTHON_EXCLUDED_URLS` is the fallback. |
| `OTEL_PYTHON_DISABLED_INSTRUMENTATIONS` | Comma-separated `django`, `psycopg`, `redis`, `requests`, `celery`, `logging`. |

If the endpoint is unset, `setup_telemetry` returns `False` and does not load the SDK.

## What is recorded

Django server spans, psycopg, redis, requests client spans, and Celery producer and consumer spans. Celery task headers carry the active context, so a trace continues from the request into the task. `requests` injects `traceparent` on outbound calls, including the MCP aggregating gateway.

Database and Redis calls made outside any span are not traced. Idle worker polls, gauge callbacks, and heartbeats would otherwise start a one span trace for every query. The same calls inside a request, a Celery task, or a manual span are recorded as children. Outbound HTTP client calls with no parent are still recorded, so the downstream service joins the trace. Wrap background work in a span when its queries should be visible, for example `trace.get_tracer(__name__).start_as_current_span('email.send')`. Set `OTEL_TRACES_SAMPLER=parentbased_always_on` to keep every call.

These paths are not traced: a URL whose path ends in `health`, `healthz`, `ready`, `readiness`, `readyz`, `live`, or `livez`, plus `/static/`, `/favicon.ico`, and `/metrics`.

Spans do not keep SQL literals (placeholders such as `%s` and `$1` stay), `db.statement.parameters`, request or response bodies, `Authorization`, cookies, or other credential headers. Query parameters whose names contain `token`, `password`, `secret`, `session`, `api_key`, or similar are replaced with `REDACTED`. Other query parameters stay. psycopg is instrumented with `capture_parameters=False`.

## Logs

While a span is active, every `LogRecord` gets:

- `trace_id` and `span_id` (32 and 16 hex characters, or `0` when there is no span)
- `otelTraceID`, `otelSpanID`, `otelTraceSampled`, `otelServiceName`

Use `TraceContextFormatter` so the format string is safe when telemetry is off:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'shellui': {
            '()': 'shellui_django.telemetry.TraceContextFormatter',
            'format': '%(asctime)s %(levelname)s %(name)s trace_id=%(trace_id)s span_id=%(span_id)s %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'shellui',
        },
    },
    'root': {'handlers': ['console'], 'level': 'INFO'},
}
```

A JSON formatter should include `trace_id` and `span_id` (or the `otelTrace*` names). SigNoz can join those fields to the trace.

## Metrics

Django records `http.server.request.duration` (seconds) and `http.server.active_requests`. Services replace Prometheus counters and histograms with:

```python
from shellui_django.telemetry import counter, histogram

emails_sent = counter('email_sent_total', description='Emails accepted for delivery')
send_seconds = histogram('email_send_seconds', unit='s', description='Time to hand off to the provider')

emails_sent.add(1, {'company_id': company_id})
send_seconds.record(elapsed_seconds, {'company_id': company_id})
```

A Prometheus name without dots is converted: `email_sent_total` becomes `email.sent`. Names that already use dots are unchanged, aside from a trailing `_total`. Instruments can be created at import time. Points recorded before `setup_telemetry` are dropped. When telemetry is off, `add` and `record` do nothing.

Keep metric attributes low cardinality. Use opaque ids, not emails or raw URLs.

`get_meter('shellui.email')` returns a meter for instruments you create yourself, or a no-op meter when telemetry is off.

## Span attributes

Attach opaque Shellui ids from a view, middleware, or task. `0` is a real company id. Emails and other free text are ignored.

```python
from shellui_django.telemetry import set_shellui_attributes

set_shellui_attributes(company_id=company_id, user_id=user_id, attributes={'agent_id': agent_id})
```

This sets `shellui.company_id`, `shellui.user_id`, and `shellui.agent_id` on the current span.

## Shutdown

Provider shutdown is registered with `atexit`. Call `shutdown_telemetry()` only if a management command must flush before `os._exit`.
