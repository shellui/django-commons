"""Signed internal calls between Shellui services (approval requests, call logs)."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any

import jwt
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings

INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS = 60
INTERNAL_ASSERTION_LEEWAY_SECONDS = 5


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
) -> str:
    now = int(time.time())
    claims = {
        'iss': _service_issuer(issuer),
        'aud': APPROVAL_AUDIENCE,
        'sub': f'agent:{agent_id}',
        'scope': APPROVAL_SCOPE,
        'company_id': company_id,
        'agent_id': agent_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    return _encode_rs256_assertion(claims, private_key_pem=private_key_pem, kid=kid)


def build_mcp_revocation_list_response_assertion(
    *,
    revoked_agent_ids: list[str],
    agents: list[dict[str, Any]] | None = None,
    cache_seconds: int = REVOCATION_CACHE_SECONDS,
    lifetime_seconds: int = REVOCATION_LIST_ASSERTION_LIFETIME_SECONDS,
) -> str:
    """Identity signs revocation poll responses so services can fail closed on tampering."""
    now = int(time.time())
    agent_rows = agents or []
    claims = {
        'iss': _identity_issuer(),
        'aud': REVOCATION_AUDIENCE,
        'sub': 'identity',
        'scope': REVOCATION_LIST_SCOPE,
        'revoked_agent_ids': [str(item) for item in revoked_agent_ids],
        'agents': agent_rows,
        'cache_seconds': int(cache_seconds),
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    try:
        return _encode_rs256_assertion(claims)
    except InternalAssertionError:
        raise InternalAssertionError(
            'Revocation list signing is not configured.',
            status=503,
        )


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
        iat = int(claims['iat'])
        exp = int(claims['exp'])
    except (KeyError, TypeError, ValueError) as exc:
        raise InternalAssertionError('Invalid iat or exp.') from exc
    if exp <= iat:
        raise InternalAssertionError('Assertion lifetime is invalid.')
    if exp - iat > max_lifetime_seconds:
        raise InternalAssertionError('Assertion lifetime exceeds the maximum allowed.')


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
    if str(claims.get('scope') or '') != REVOCATION_LIST_SCOPE:
        raise InternalAssertionError('Revocation list scope mismatch.')
    if str(claims.get('sub') or '') != 'identity':
        raise InternalAssertionError('Revocation list issuer subject mismatch.')
    claimed_ids = [str(item) for item in (claims.get('revoked_agent_ids') or [])]
    claimed_cache = int(claims.get('cache_seconds') or 0)
    body_ids = payload.get('revoked_agent_ids')
    if body_ids is not None:
        normalized_body = [str(item) for item in body_ids]
        if normalized_body != claimed_ids:
            raise InternalAssertionError('Revocation list body mismatch.')
    body_cache = payload.get('cache_seconds')
    if body_cache is not None and int(body_cache) != claimed_cache:
        raise InternalAssertionError('Revocation list cache mismatch.')
    claimed_agents = claims.get('agents') or []
    body_agents = payload.get('agents')
    if body_agents is not None and body_agents != claimed_agents:
        raise InternalAssertionError('Revocation list agents mismatch.')
    return {
        'revoked_agent_ids': claimed_ids,
        'agents': claimed_agents,
        'cache_seconds': claimed_cache,
    }


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
