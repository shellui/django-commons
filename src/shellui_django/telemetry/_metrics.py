"""Metric helpers. OpenTelemetry is imported only after telemetry is active."""

from __future__ import annotations

import re
from typing import Any

from shellui_django import __version__
from shellui_django.telemetry._state import state

_TOTAL_SUFFIXES = ('_total', '.total')
_INSTRUMENT_NAME = re.compile(r'^[a-z][a-z0-9_.]{0,254}$')
_DOTS = re.compile(r'\.+')


def canonical_metric_name(name: str) -> str:
    """Turn a Prometheus-style name into an OpenTelemetry instrument name.

    ``email_sent_total`` becomes ``email.sent``. Names that already contain a
    dot are kept, aside from a trailing ``_total`` or ``.total``.
    """
    cleaned = name.strip().lower()
    for suffix in _TOTAL_SUFFIXES:
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    if '.' not in cleaned:
        cleaned = cleaned.replace('_', '.')
    cleaned = _DOTS.sub('.', cleaned).strip('.')
    if not cleaned or not _INSTRUMENT_NAME.fullmatch(cleaned):
        raise ValueError(f'invalid metric name {name!r}')
    return cleaned


class _NoOpCounter:
    def add(self, amount: int | float, attributes: dict[str, Any] | None = None) -> None:
        return None


class _NoOpHistogram:
    def record(self, amount: int | float, attributes: dict[str, Any] | None = None) -> None:
        return None


class _NoOpMeter:
    def create_counter(self, name: str, unit: str = '', description: str = '') -> _NoOpCounter:
        return _NoOpCounter()

    def create_histogram(self, name: str, unit: str = '', description: str = '') -> _NoOpHistogram:
        return _NoOpHistogram()


_NOOP_METER = _NoOpMeter()


def get_meter(name: str = 'shellui'):
    """Return a meter, or a no-op meter when telemetry is off."""
    if not state.active:
        return _NOOP_METER
    from opentelemetry import metrics

    return metrics.get_meter(name, __version__)


class _LazyInstrument:
    def __init__(self, kind: str, name: str, unit: str, description: str, meter_name: str) -> None:
        self._kind = kind
        self._name = canonical_metric_name(name)
        self._unit = unit
        self._description = description
        self._meter_name = meter_name
        self._instrument: Any = None
        self._generation = -1

    def _bound(self) -> Any:
        generation = state.generation
        if self._instrument is not None and self._generation == generation:
            return self._instrument
        meter = get_meter(self._meter_name)
        if self._kind == 'counter':
            self._instrument = meter.create_counter(self._name, unit=self._unit, description=self._description)
        else:
            self._instrument = meter.create_histogram(self._name, unit=self._unit, description=self._description)
        self._generation = generation
        return self._instrument


class _LazyCounter(_LazyInstrument):
    def __init__(self, name: str, unit: str, description: str, meter_name: str) -> None:
        super().__init__('counter', name, unit, description, meter_name)

    def add(self, amount: int | float, attributes: dict[str, Any] | None = None) -> None:
        self._bound().add(amount, attributes or {})


class _LazyHistogram(_LazyInstrument):
    def __init__(self, name: str, unit: str, description: str, meter_name: str) -> None:
        super().__init__('histogram', name, unit, description, meter_name)

    def record(self, amount: int | float, attributes: dict[str, Any] | None = None) -> None:
        self._bound().record(amount, attributes or {})


def counter(
    name: str,
    *,
    unit: str = '1',
    description: str = '',
    meter_name: str = 'shellui',
) -> _LazyCounter:
    """Create a counter. Safe to call before :func:`setup_telemetry`.

    Points recorded before setup are dropped. Later points use the real meter
    once setup has enabled telemetry, and stay no-ops when it has not.
    """
    return _LazyCounter(name, unit, description, meter_name)


def histogram(
    name: str,
    *,
    unit: str = '1',
    description: str = '',
    meter_name: str = 'shellui',
) -> _LazyHistogram:
    """Create a histogram. Same lifetime rules as :func:`counter`."""
    return _LazyHistogram(name, unit, description, meter_name)
