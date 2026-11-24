"""Log formatter that tolerates missing trace ids. No OpenTelemetry imports."""

from __future__ import annotations

import logging

_DEFAULTS: tuple[tuple[str, object], ...] = (
    ('trace_id', '0'),
    ('span_id', '0'),
    ('otelTraceID', '0'),
    ('otelSpanID', '0'),
    ('otelTraceSampled', False),
    ('otelServiceName', ''),
)


class TraceContextFormatter(logging.Formatter):
    """Formatter that fills trace ids when telemetry is off.

    When telemetry is on, records already carry ``trace_id``, ``span_id``,
    ``otelTraceID``, ``otelSpanID``, ``otelTraceSampled``, and
    ``otelServiceName``. When it is off, those fields are zeros so a format
    string can always include them.
    """

    def format(self, record: logging.LogRecord) -> str:
        for name, default in _DEFAULTS:
            if not hasattr(record, name):
                setattr(record, name, default)
        return super().format(record)
