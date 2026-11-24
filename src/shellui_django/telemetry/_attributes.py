"""Attach opaque Shellui ids to the current span. OpenTelemetry is imported only when active."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping

from shellui_django.telemetry._state import state

logger = logging.getLogger(__name__)

_OPAQUE_ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
_ATTRIBUTE_KEY = re.compile(r'^[a-z][a-z0-9_]{0,40}$')
_PII_KEY = re.compile(r'(email|e_mail|phone|name|address|firstname|lastname|password|secret)')


def _opaque_id(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or not _OPAQUE_ID.fullmatch(text):
        return None
    return text


def _attribute_key(key: str) -> str | None:
    normalized = key.strip().lower().replace('-', '_')
    if normalized.startswith('shellui.'):
        normalized = normalized[len('shellui.') :]
    if not _ATTRIBUTE_KEY.fullmatch(normalized) or _PII_KEY.search(normalized):
        return None
    return f'shellui.{normalized}'


def set_shellui_attributes(
    *,
    company_id: str | int | None = None,
    user_id: str | int | None = None,
    attributes: Mapping[str, str | int | bool] | None = None,
) -> None:
    """Set opaque Shellui ids on the current span.

    ``company_id`` and ``user_id`` are recorded as ``shellui.company_id`` and
    ``shellui.user_id``. Values must be integers or short opaque tokens.
    Emails, names, and other free text are dropped. ``0`` is a real company id.
    Extra ``attributes`` are stored under the ``shellui.`` prefix with the same
    rules. The call does nothing when telemetry is off or there is no recording span.
    """
    if not state.active:
        return

    from opentelemetry import trace

    span = trace.get_current_span()
    if not span.is_recording():
        return

    resolved: dict[str, str | bool] = {}
    if company_id is not None:
        company = _opaque_id(company_id)
        if company is None:
            logger.warning('shellui telemetry: skipped shellui.company_id because the value is not an opaque id')
        else:
            resolved['shellui.company_id'] = company
    if user_id is not None:
        user = _opaque_id(user_id)
        if user is None:
            logger.warning('shellui telemetry: skipped shellui.user_id because the value is not an opaque id')
        else:
            resolved['shellui.user_id'] = user

    for raw_key, raw_value in (attributes or {}).items():
        key = _attribute_key(str(raw_key))
        if key is None:
            logger.warning('shellui telemetry: skipped span attribute %s', raw_key)
            continue
        if isinstance(raw_value, bool):
            resolved[key] = raw_value
            continue
        opaque = _opaque_id(raw_value)
        if opaque is None:
            logger.warning('shellui telemetry: skipped span attribute %s because the value is not an opaque id', key)
            continue
        resolved[key] = opaque

    if resolved:
        span.set_attributes(resolved)
