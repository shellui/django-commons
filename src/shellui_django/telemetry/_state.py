"""Process-local telemetry state. Importing this module does not import OpenTelemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TelemetryState:
    """Mutable state shared by setup, metrics, and tests."""

    active: bool = False
    pid: int | None = None
    generation: int = 0
    tracer_provider: Any = None
    meter_provider: Any = None
    instrumentors: list[Any] = field(default_factory=list)
    previous_log_factory: Any = None
    service_name: str = ''

    def clear(self) -> None:
        self.active = False
        self.pid = None
        self.tracer_provider = None
        self.meter_provider = None
        self.instrumentors = []
        self.previous_log_factory = None
        self.service_name = ''
        self.generation += 1


state = TelemetryState()
