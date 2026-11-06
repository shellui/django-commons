"""Signed internal calls between Shellui services (approval requests, call logs)."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Callable
from typing import Any

import jwt
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings

from shellui_django.mcp.identity_jwks import IdentityJwksError, jwt_unix_timestamp_claim_strict

INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS = 60
INTERNAL_ASSERTION_LEEWAY_SECONDS = 5
REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS = 600


def _identity_issuer() -> str:
    return (api_settings.ISSUER or getattr(settings, 'JWT_ISSUER', None) or '').strip()


def _service_issuer(explicit: str | None = None) -> str:
    if explicit and explicit.strip():
        return explicit.strip().rstrip('/')
    configured = getattr(settings, 'JWT_ISSUER', None) or api_settings.ISSUER or ''
    return str(configured).strip().rstrip('/')


APPROVAL_AUDIENCE = 'shellui-mcp-approval'
APPROVAL_SCOPE = 'mcp.approval.create'
CALL_LOG_AUDIENCE = 'shellui-mcp-call-log'
CALL_LOG_SCOPE = 'mcp.call_log.create'
REVOCATION_AUDIENCE = 'shellui-mcp-revocation'
REVOCATION_SCOPE = 'mcp.revocation.read'
REVOCATION_LIST_SCOPE = 'mcp.revocation.list'
REVOCATION_CACHE_SECONDS = 30
REVOCATION_LIST_ASSERTION_LIFETIME_SECONDS = REVOCATION_CACHE_SECONDS


def _strict_non_negative_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise InternalAssertionError(f'{field} must be a non-negative integer.')
    if isinstance(value, int):
        if value < 0:
            raise InternalAssertionError(f'{field} must be non-negative.')
        return value
    raise InternalAssertionError(f'{field} must be a non-negative integer.')


def _revocation_version_kwarg(value: Any, *, field: str) -> int | None:
    """Optional revocation metadata: strict non-negative int or None (omit from JWT)."""
    if value is None:
        return None
    return _strict_non_negative_int(value, field=field)


def _approval_grant_version_kwarg(value: Any, *, field: str) -> int | None:
    """Optional personal grant baseline: non-negative int or None (omit); never defaulted."""
    if value is None:
        return None
    return _strict_non_negative_int(value, field=field)


def _delegated_grant_version_kwarg(value: Any, *, field: str) -> int:
    """Required for global delegated approvals: non-negative int."""
    if value is None:
        raise InternalAssertionError(f'{field} is required for delegated global authority.')
    return _strict_non_negative_int(value, field=field)


def _delegated_binding_version_kwarg(value: Any, *, field: str) -> int:
    """Required with global_company_id; preserves explicit zero (`is not None`)."""
    if value is None:
        raise InternalAssertionError(
            f'{field} is required when global_company_id is set (use 0 for the personal baseline).'
        )
    return _strict_non_negative_int(value, field=field)


def _non_negative_int_from_json_body(value: Any, *, field: str) -> int:
    """Legacy HTTP envelope: int or decimal digit string only (no bool/float)."""
    if isinstance(value, bool):
        raise InternalAssertionError(f'{field} must be a non-negative integer.')
    if isinstance(value, int):
        return _strict_non_negative_int(value, field=field)
    if isinstance(value, str):
        s = value.strip()
        if not s.isdigit():
            raise InternalAssertionError(f'{field} must be a non-negative integer.')
        return int(s)
    raise InternalAssertionError(f'{field} must be a non-negative integer.')


def _jwt_optional_int_claim(value: Any, *, field: str) -> int:
    """JWT claim value: int or legacy decimal string (Identity compatibility). Rejects bool/float."""
    if isinstance(value, bool):
        raise InternalAssertionError(f'{field} must be a non-negative integer.')
    if isinstance(value, int):
        return _strict_non_negative_int(value, field=field)
    if isinstance(value, str):
        s = value.strip()
        if not s or not s.isdigit():
            raise InternalAssertionError(f'{field} must be a non-negative integer.')
        return int(s)
    raise InternalAssertionError(f'{field} must be a non-negative integer.')


def _jwt_unix_timestamp_claim(value: Any, *, field: str) -> int:
    """``iat`` / ``exp`` after JWT decode (same rules as ``jwt_unix_timestamp_claim_strict``)."""
    try:
        return jwt_unix_timestamp_claim_strict(value, field=field)
    except IdentityJwksError as exc:
        raise InternalAssertionError(str(exc)) from exc


def _normalize_uuid_string(value: str | None, *, field: str) -> str:
    raw = str(value or '').strip()
    if not raw:
        raise InternalAssertionError(f'{field} is required when provided.')
    try:
        parsed = uuid.UUID(raw)
    except ValueError as exc:
        raise InternalAssertionError(f'{field} must be a UUID string.') from exc
    return str(parsed)


class InternalAssertionError(Exception):
    def __init__(self, message: str, *, status: int = 401):
        super().__init__(message)
        self.message = message
        self.status = status


def _signing_material(
    *,
    private_key_pem: str | None = None,
    kid: str | None = None,
) -> tuple[str, str]:
    if private_key_pem and private_key_pem.strip():
        pem = private_key_pem.strip()
        key_id = (kid or '').strip() or getattr(settings, 'JWT_ACTIVE_KEY_ID', '') or ''
        return pem, key_id
    signing = getattr(settings, 'JWT_SIGNING_KEY', None)
    if signing is None:
        raise InternalAssertionError(
            'Service assertion signing is not configured.',
            status=503,
        )
    pem = getattr(signing, 'private_pem', None) or ''
    if not pem:
        raise InternalAssertionError(
            'Service assertion signing is not configured.',
            status=503,
        )
    key_id = (
        (kid or '').strip()
        or getattr(signing, 'kid', None)
        or getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
        or ''
    )
    return pem, key_id


def _encode_rs256_assertion(
    claims: dict[str, Any],
    *,
    private_key_pem: str | None = None,
    kid: str | None = None,
) -> str:
    pem, key_id = _signing_material(private_key_pem=private_key_pem, kid=kid)
    headers: dict[str, str] | None = {'kid': key_id} if key_id else None
    token = jwt.encode(claims, pem, algorithm='RS256', headers=headers)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def build_mcp_approval_assertion(
    *,
    company_id: int,
    agent_id: str,
    service: str,
    action: str,
    arguments_hash: str,
    audience_url: str,
    lifetime_seconds: int = 60,
    private_key_pem: str | None = None,
    kid: str | None = None,
    issuer: str | None = None,
    grant_version: int | None = None,
    global_company_id: str | None = None,
    company_binding_version: int | None = None,
) -> str:
    now = int(time.time())
    company_id_int = _strict_non_negative_int(company_id, field='company_id')
    has_global_company = global_company_id is not None
    if has_global_company:
        binding_ver_int = _delegated_binding_version_kwarg(company_binding_version, field='company_binding_version')
        grant_ver_int = _delegated_grant_version_kwarg(grant_version, field='grant_version')
    else:
        if company_binding_version is not None:
            raise InternalAssertionError(
                'company_binding_version must be omitted when global_company_id is not set.'
            )
        grant_ver_int = _approval_grant_version_kwarg(grant_version, field='grant_version')
    claims: dict[str, Any] = {
        'iss': _service_issuer(issuer),
        'aud': APPROVAL_AUDIENCE,
        'sub': f'agent:{agent_id}',
        'scope': APPROVAL_SCOPE,
        'company_id': company_id_int,
        'agent_id': agent_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    if grant_ver_int is not None:
        claims['grant_version'] = grant_ver_int
    if has_global_company:
        claims['global_company_id'] = _normalize_uuid_string(global_company_id, field='global_company_id')
        claims['company_binding_version'] = binding_ver_int
    return _encode_rs256_assertion(claims, private_key_pem=private_key_pem, kid=kid)


def build_mcp_revocation_list_response_assertion(
    *,
    revoked_agent_ids: list[str],
    agents: list[dict[str, Any]] | None = None,
    cache_seconds: int = REVOCATION_CACHE_SECONDS,
    lifetime_seconds: int = REVOCATION_LIST_ASSERTION_LIFETIME_SECONDS,
    revocation_policy_version: int | None = None,
    max_active_grant_version: int | None = None,
) -> str:
    """Identity signs revocation poll responses so services can fail closed on tampering."""
    now = int(time.time())
    agent_rows = agents or []
    if lifetime_seconds <= 0:
        raise InternalAssertionError('lifetime_seconds must be positive.')
    if lifetime_seconds > REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS:
        raise InternalAssertionError('Revocation list assertion lifetime exceeds the maximum allowed.')
    cache_val = _cache_seconds_claim(cache_seconds, field='cache_seconds')
    policy_ver = _revocation_version_kwarg(revocation_policy_version, field='revocation_policy_version')
    max_grant_ver = _revocation_version_kwarg(max_active_grant_version, field='max_active_grant_version')
    claims: dict[str, Any] = {
        'iss': _identity_issuer(),
        'aud': REVOCATION_AUDIENCE,
        'sub': 'identity',
        'scope': REVOCATION_LIST_SCOPE,
        'revoked_agent_ids': [str(item) for item in revoked_agent_ids],
        'agents': agent_rows,
        'cache_seconds': cache_val,
        'iat': now,
        'exp': now + int(lifetime_seconds),
        'jti': uuid.uuid4().hex,
    }
    if policy_ver is not None:
        claims['revocation_policy_version'] = policy_ver
    if max_grant_ver is not None:
        claims['max_active_grant_version'] = max_grant_ver
    try:
        return _encode_rs256_assertion(claims)
    except InternalAssertionError as exc:
        raise InternalAssertionError(
            'Revocation list signing is not configured.',
            status=503,
        ) from exc


def build_mcp_revocation_assertion(
    *,
    audience_url: str,
    lifetime_seconds: int = 60,
    private_key_pem: str | None = None,
    kid: str | None = None,
    issuer: str | None = None,
) -> str:
    now = int(time.time())
    claims = {
        'iss': _service_issuer(issuer),
        'aud': REVOCATION_AUDIENCE,
        'sub': 'service',
        'scope': REVOCATION_SCOPE,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    return _encode_rs256_assertion(claims, private_key_pem=private_key_pem, kid=kid)


def build_mcp_call_log_assertion(
    *,
    audience_url: str,
    lifetime_seconds: int = 60,
    private_key_pem: str | None = None,
    kid: str | None = None,
    issuer: str | None = None,
) -> str:
    now = int(time.time())
    claims = {
        'iss': _service_issuer(issuer),
        'aud': CALL_LOG_AUDIENCE,
        'sub': 'service',
        'scope': CALL_LOG_SCOPE,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    return _encode_rs256_assertion(claims, private_key_pem=private_key_pem, kid=kid)


def _normalize_bearer_token(raw_token: str) -> str:
    if not raw_token or not raw_token.strip():
        raise InternalAssertionError('Missing assertion.')
    token = raw_token.strip()
    if token.lower().startswith('bearer '):
        token = token[7:].strip()
    if not token:
        raise InternalAssertionError('Missing assertion.')
    return token


def _assert_lifetime_within_limit(claims: dict[str, Any], *, max_lifetime_seconds: int) -> None:
    try:
        iat = _jwt_unix_timestamp_claim(claims['iat'], field='iat')
        exp = _jwt_unix_timestamp_claim(claims['exp'], field='exp')
    except KeyError as exc:
        raise InternalAssertionError('Invalid iat or exp.') from exc
    if exp <= iat:
        raise InternalAssertionError('Assertion lifetime is invalid.')
    if exp - iat > max_lifetime_seconds:
        raise InternalAssertionError('Assertion lifetime exceeds the maximum allowed.')


def _assert_identity_revocation_token_invariants(claims: dict[str, Any]) -> None:
    """Clock and span checks after JWKS verification (aligned with decode leeway)."""
    try:
        iat = _jwt_unix_timestamp_claim(claims['iat'], field='iat')
        exp = _jwt_unix_timestamp_claim(claims['exp'], field='exp')
    except KeyError as exc:
        raise InternalAssertionError('Invalid iat or exp.') from exc
    if exp <= iat:
        raise InternalAssertionError('Revocation list assertion exp must be after iat.')
    span = exp - iat
    if span > REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS:
        raise InternalAssertionError('Revocation list assertion lifetime exceeds the maximum allowed.')
    now = int(time.time())
    # Mirror PyJWT exp/iat skew bounds used when decoding the Identity JWT.
    if iat > now + INTERNAL_ASSERTION_LEEWAY_SECONDS:
        raise InternalAssertionError('Revocation list assertion iat is in the future.')
    if exp <= now - INTERNAL_ASSERTION_LEEWAY_SECONDS:
        raise InternalAssertionError('Revocation list assertion is expired.')
    jti = str(claims.get('jti') or '').strip()
    if not jti:
        raise InternalAssertionError('Missing jti.')


def _signed_int_body_matches_claim(*, claim_value: Any, body_value: Any, field: str) -> int:
    """Compare JWT claim (int or legacy digit string) to HTTP body (int or legacy digit string)."""
    claim_int = _jwt_optional_int_claim(claim_value, field=field)
    body_int = _non_negative_int_from_json_body(body_value, field=field)
    if body_int != claim_int:
        raise InternalAssertionError('Revocation list body mismatch.')
    return claim_int


def _cache_seconds_claim(value: Any, *, field: str) -> int:
    v = _jwt_optional_int_claim(value, field=field)
    if v <= 0:
        raise InternalAssertionError(f'{field} must be positive.')
    if v > REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS:
        raise InternalAssertionError(f'{field} exceeds the maximum allowed.')
    return v


def _agent_global_pair_present(row: dict[str, Any]) -> tuple[bool, bool]:
    """True when global_company_id / company_binding_version are present (not None); never uses truthiness on ints."""
    g = row.get('global_company_id', None)
    b = row.get('company_binding_version', None)
    g_pres = g is not None
    b_pres = b is not None
    return g_pres, b_pres


def _agent_row_version_int(value: Any, *, field: str) -> int:
    """Signed ``agents[]`` row: non-negative int, or legacy decimal string (no bool/float)."""
    return _jwt_optional_int_claim(value, field=field)


def _validate_trusted_agent_authority_snapshots(
    agents: list[Any],
    *,
    max_active_grant_version: int | None,
) -> list[dict[str, Any]]:
    """
    Validate per-agent global binding snapshots for Identity-signed revocation rows.

    Personal agents: ``global_company_id`` and ``company_binding_version`` must both be absent
    or JSON ``null`` (never one side set). Optional ``grant_version`` may be a non-negative int
    (including ``0``) or omitted / ``null``. Personal ``grant_version`` is not capped by
    ``max_active_grant_version`` (that cap applies to delegated snapshots only).

    Delegated agents: ``global_company_id``, ``company_binding_version``, and ``grant_version``
    are all required non-negative ints / UUID string; ``company_binding_version`` may be ``0``.

    When ``max_active_grant_version`` is signed (non-``None``), delegated rows with
    ``grant_version`` greater than the cap are marked ``mcp_authority_snapshot_rejected`` (fail
    closed for that row only). The cap is a signed policy snapshot, not a grant to widen authority.
    """
    if not isinstance(agents, list):
        raise InternalAssertionError('Revocation list agents must be a list.')
    out: list[dict[str, Any]] = []
    for raw in agents:
        if not isinstance(raw, dict):
            raise InternalAssertionError('Revocation list agents must be objects.')
        row = dict(raw)
        g_pres, b_pres = _agent_global_pair_present(row)
        if g_pres != b_pres:
            raise InternalAssertionError(
                'Revocation list agent global_company_id and company_binding_version must both be set or both null.'
            )
        if g_pres:
            g = _normalize_uuid_string(row.get('global_company_id'), field='global_company_id')
            row['global_company_id'] = g
            row['company_binding_version'] = _agent_row_version_int(
                row.get('company_binding_version'),
                field='company_binding_version',
            )
            if 'grant_version' not in row or row.get('grant_version') is None:
                raise InternalAssertionError('grant_version is required when global_company_id is set.')
            row['grant_version'] = _agent_row_version_int(row.get('grant_version'), field='grant_version')
            if max_active_grant_version is not None and row['grant_version'] > max_active_grant_version:
                row['mcp_authority_snapshot_rejected'] = True
                row['mcp_authority_snapshot_fingerprint'] = None
            else:
                row['mcp_authority_snapshot_rejected'] = False
                payload = {
                    'company_binding_version': row['company_binding_version'],
                    'global_company_id': g,
                    'grant_version': row['grant_version'],
                }
                row['mcp_authority_snapshot_fingerprint'] = hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
                ).hexdigest()
        else:
            row.pop('global_company_id', None)
            row.pop('company_binding_version', None)
            gv = row.get('grant_version', None)
            if gv is None:
                row.pop('grant_version', None)
            else:
                row['grant_version'] = _agent_row_version_int(gv, field='grant_version')
            row['mcp_authority_snapshot_fingerprint'] = None
            row['mcp_authority_snapshot_rejected'] = False
        out.append(row)
    return out


def verify_rs256_mcp_assertion(
    raw_token: str,
    public_jwks_or_pem: dict[str, Any] | str,
    *,
    expected_issuer: str,
    expected_audience: str,
    expected_scope: str,
    expected_target: str | None = None,
    register_jti: Callable[[str], bool] | None = None,
    max_lifetime_seconds: int = INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS,
) -> dict[str, Any]:
    """Verify a service-signed RS256 internal MCP assertion using caller JWKS or PEM."""
    from shellui_django.mcp.identity_jwks import IdentityJwksError, resolve_public_verification_key

    token = _normalize_bearer_token(raw_token)
    issuer = (expected_issuer or '').strip().rstrip('/')
    if not issuer:
        raise InternalAssertionError('expected_issuer is required.')
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise InternalAssertionError('Invalid assertion.') from exc
    alg = str(header.get('alg') or '')
    if alg != 'RS256':
        raise InternalAssertionError('Internal MCP assertion must use RS256.')
    try:
        key = resolve_public_verification_key(token, public_jwks_or_pem)
    except IdentityJwksError as exc:
        raise InternalAssertionError(str(exc)) from exc
    try:
        payload = jwt.decode(
            token,
            key=key,
            algorithms=['RS256'],
            audience=expected_audience,
            issuer=issuer,
            leeway=INTERNAL_ASSERTION_LEEWAY_SECONDS,
            options={'require': ['exp', 'iat', 'sub', 'scope', 'jti']},
        )
    except jwt.PyJWTError as exc:
        raise InternalAssertionError('Invalid assertion.') from exc
    scope = str(payload.get('scope') or '')
    if scope != expected_scope:
        raise InternalAssertionError('Assertion scope mismatch.')
    aud = payload.get('aud')
    if isinstance(aud, list):
        if expected_audience not in aud:
            raise InternalAssertionError('Assertion audience mismatch.')
    elif str(aud or '') != expected_audience:
        raise InternalAssertionError('Assertion audience mismatch.')
    if expected_target:
        target = str(payload.get('target') or '').rstrip('/')
        if target and target != expected_target.rstrip('/'):
            raise InternalAssertionError('Assertion target mismatch.')
    _assert_lifetime_within_limit(payload, max_lifetime_seconds=max_lifetime_seconds)
    jti = str(payload.get('jti') or '').strip()
    if not jti:
        raise InternalAssertionError('Missing jti.')
    if register_jti is not None and not register_jti(jti):
        raise InternalAssertionError('Assertion replay detected.')
    return payload


def verify_mcp_internal_assertion(
    raw_token: str,
    public_jwks_or_pem: dict[str, Any] | str,
    *,
    expected_issuer: str,
    expected_audience: str,
    expected_scope: str,
    expected_target: str | None = None,
    register_jti: Callable[[str], bool] | None = None,
    max_lifetime_seconds: int = INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS,
) -> dict[str, Any]:
    return verify_rs256_mcp_assertion(
        raw_token,
        public_jwks_or_pem,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        expected_scope=expected_scope,
        expected_target=expected_target,
        register_jti=register_jti,
        max_lifetime_seconds=max_lifetime_seconds,
    )


def _revocation_list_assertion_token(payload: dict[str, Any]) -> str:
    token = payload.get('revocation_assertion') or payload.get('assertion')
    if not token or not str(token).strip():
        raise InternalAssertionError('Missing revocation list assertion.')
    return str(token).strip()


def verify_mcp_revocation_list_response(
    payload: dict[str, Any],
    *,
    expected_issuer: str,
    identity_jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    jwks_timeout: float = 10.0,
) -> dict[str, Any]:
    """Verify Identity's signed revocation poll response via RS256 JWKS; raises when untrusted."""
    from shellui_django.mcp.identity_jwks import (
        IdentityJwksError,
        decode_identity_rs256_jwt,
        identity_jwks_url_for_issuer,
    )

    token = _revocation_list_assertion_token(payload)
    issuer = (expected_issuer or '').strip().rstrip('/')
    if not issuer:
        raise InternalAssertionError('expected_issuer is required.')
    jwks_url = identity_jwks_url or identity_jwks_url_for_issuer(issuer)
    try:
        claims = decode_identity_rs256_jwt(
            token,
            audience=REVOCATION_AUDIENCE,
            issuer=issuer,
            jwks_url=jwks_url,
            jwks=jwks,
            timeout=jwks_timeout,
        )
    except IdentityJwksError as exc:
        raise InternalAssertionError(str(exc)) from exc
    try:
        _assert_identity_revocation_token_invariants(claims)
    except InternalAssertionError:
        raise
    if str(claims.get('scope') or '') != REVOCATION_LIST_SCOPE:
        raise InternalAssertionError('Revocation list scope mismatch.')
    if str(claims.get('sub') or '') != 'identity':
        raise InternalAssertionError('Revocation list issuer subject mismatch.')
    claimed_ids = [str(item) for item in (claims.get('revoked_agent_ids') or [])]
    claimed_cache = _cache_seconds_claim(claims.get('cache_seconds'), field='cache_seconds')
    body_ids = payload.get('revoked_agent_ids')
    if body_ids is not None:
        normalized_body = [str(item) for item in body_ids]
        if normalized_body != claimed_ids:
            raise InternalAssertionError('Revocation list body mismatch.')
    body_cache = payload.get('cache_seconds')
    if body_cache is not None:
        body_cache_int = _non_negative_int_from_json_body(body_cache, field='cache_seconds')
        if body_cache_int != claimed_cache:
            raise InternalAssertionError('Revocation list cache mismatch.')
    max_grant_cap: int | None
    if 'max_active_grant_version' in claims:
        if 'max_active_grant_version' not in payload:
            raise InternalAssertionError('Revocation list body mismatch.')
        max_grant_cap = _signed_int_body_matches_claim(
            claim_value=claims['max_active_grant_version'],
            body_value=payload['max_active_grant_version'],
            field='max_active_grant_version',
        )
    else:
        if 'max_active_grant_version' in payload:
            raise InternalAssertionError('Revocation list body mismatch.')
        max_grant_cap = None
    claimed_agents_raw = claims.get('agents') or []
    body_agents = payload.get('agents')
    if body_agents is not None and body_agents != claimed_agents_raw:
        raise InternalAssertionError('Revocation list agents mismatch.')
    validated_agents = _validate_trusted_agent_authority_snapshots(
        claimed_agents_raw,
        max_active_grant_version=max_grant_cap,
    )
    out: dict[str, Any] = {
        'revoked_agent_ids': claimed_ids,
        'agents': validated_agents,
        'cache_seconds': claimed_cache,
    }
    if 'revocation_policy_version' in claims:
        if 'revocation_policy_version' not in payload:
            raise InternalAssertionError('Revocation list body mismatch.')
        policy_int = _signed_int_body_matches_claim(
            claim_value=claims['revocation_policy_version'],
            body_value=payload['revocation_policy_version'],
            field='revocation_policy_version',
        )
        out['revocation_policy_version'] = policy_int
    else:
        if 'revocation_policy_version' in payload:
            raise InternalAssertionError('Revocation list body mismatch.')
        out['revocation_policy_version'] = None
    out['max_active_grant_version'] = max_grant_cap
    return out


def parse_trusted_revocation_poll_response(
    payload: dict[str, Any],
    *,
    expected_issuer: str,
    identity_jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    jwks_timeout: float = 10.0,
) -> tuple[frozenset[str], int, list[dict[str, Any]]]:
    """Return trusted revoked ids, cache TTL, and agent rows; fail closed on any problem."""
    trusted = verify_mcp_revocation_list_response(
        payload,
        expected_issuer=expected_issuer,
        identity_jwks_url=identity_jwks_url,
        jwks=jwks,
        jwks_timeout=jwks_timeout,
    )
    ids = frozenset(trusted['revoked_agent_ids'])
    cache_seconds = int(trusted['cache_seconds'] or REVOCATION_CACHE_SECONDS)
    agents = list(trusted.get('agents') or [])
    return ids, cache_seconds, agents
