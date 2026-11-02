"""RS256 JWT delegation: gateway requests Identity to mint downstream MCP access tokens."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt

DOWNSTREAM_TOKEN_AUDIENCE = 'shellui-mcp-downstream-token'
DOWNSTREAM_TOKEN_SCOPE = 'mcp.downstream_token.mint'
DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS = 60
DOWNSTREAM_TOKEN_REQUEST_LEEWAY_SECONDS = 5

_REQUIRED_CLAIMS = (
    'iss',
    'aud',
    'scope',
    'agent_id',
    'company_id',
    'resource',
    'jti',
    'iat',
    'exp',
)


class DownstreamTokenRequestError(Exception):
    def __init__(self, message: str, *, status: int = 401):
        super().__init__(message)
        self.message = message
        self.status = status


def sign_downstream_token_request(
    private_key_pem: str,
    kid: str,
    issuer: str,
    agent_id: str,
    company_id: int,
    resource: str,
    ttl: int,
) -> str:
    """Sign a short-lived RS256 request JWT for Identity's downstream token mint endpoint."""
    if ttl <= 0 or ttl > DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS:
        raise DownstreamTokenRequestError(
            f'ttl must be between 1 and {DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS} seconds.'
        )
    pem = (private_key_pem or '').strip()
    if not pem:
        raise DownstreamTokenRequestError('private_key_pem is required.')
    iss = (issuer or '').strip()
    if not iss:
        raise DownstreamTokenRequestError('issuer is required.')
    agent = (agent_id or '').strip()
    if not agent:
        raise DownstreamTokenRequestError('agent_id is required.')
    res = (resource or '').strip()
    if not res:
        raise DownstreamTokenRequestError('resource is required.')
    now = int(time.time())
    claims = {
        'iss': iss,
        'aud': DOWNSTREAM_TOKEN_AUDIENCE,
        'scope': DOWNSTREAM_TOKEN_SCOPE,
        'agent_id': agent,
        'company_id': int(company_id),
        'resource': res,
        'jti': uuid.uuid4().hex,
        'iat': now,
        'exp': now + int(ttl),
    }
    headers: dict[str, str] | None = None
    key_id = (kid or '').strip()
    if key_id:
        headers = {'kid': key_id}
    token = jwt.encode(claims, pem, algorithm='RS256', headers=headers)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def _normalize_bearer_token(raw_token: str) -> str:
    if not raw_token or not raw_token.strip():
        raise DownstreamTokenRequestError('Missing downstream token request JWT.')
    token = raw_token.strip()
    if token.lower().startswith('bearer '):
        token = token[7:].strip()
    if not token:
        raise DownstreamTokenRequestError('Missing downstream token request JWT.')
    return token


def _resolve_verification_key(token: str, public_jwks_or_pem: dict[str, Any] | str) -> Any:
    if isinstance(public_jwks_or_pem, str):
        pem = public_jwks_or_pem.strip()
        if not pem:
            raise DownstreamTokenRequestError('Verification key is required.')
        return pem
    if isinstance(public_jwks_or_pem, dict):
        from shellui_django.mcp.identity_jwks import IdentityJwksError, resolve_verification_key

        try:
            return resolve_verification_key(token, public_jwks_or_pem)
        except IdentityJwksError as exc:
            raise DownstreamTokenRequestError(str(exc)) from exc
    raise DownstreamTokenRequestError('public_jwks_or_pem must be a PEM string or JWKS document.')


def _assert_lifetime_within_limit(claims: dict[str, Any]) -> None:
    try:
        iat = int(claims['iat'])
        exp = int(claims['exp'])
    except (KeyError, TypeError, ValueError) as exc:
        raise DownstreamTokenRequestError('Invalid iat or exp.') from exc
    if exp <= iat:
        raise DownstreamTokenRequestError('Token lifetime is invalid.')
    if exp - iat > DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS:
        raise DownstreamTokenRequestError('Token lifetime exceeds the maximum allowed.')


def verify_downstream_token_request(
    token: str,
    public_jwks_or_pem: dict[str, Any] | str,
    expected_issuer: str,
) -> dict[str, Any]:
    """Verify a gateway-signed downstream token request; returns claims (including ``jti`` for one-time use)."""
    normalized = _normalize_bearer_token(token)
    issuer = (expected_issuer or '').strip().rstrip('/')
    if not issuer:
        raise DownstreamTokenRequestError('expected_issuer is required.')
    try:
        header = jwt.get_unverified_header(normalized)
    except jwt.PyJWTError as exc:
        raise DownstreamTokenRequestError('Invalid downstream token request JWT.') from exc
    alg = str(header.get('alg') or '')
    if alg != 'RS256':
        raise DownstreamTokenRequestError('Downstream token request JWT must use RS256.')
    key = _resolve_verification_key(normalized, public_jwks_or_pem)
    try:
        claims = jwt.decode(
            normalized,
            key=key,
            algorithms=['RS256'],
            audience=DOWNSTREAM_TOKEN_AUDIENCE,
            issuer=issuer,
            leeway=DOWNSTREAM_TOKEN_REQUEST_LEEWAY_SECONDS,
            options={'require': list(_REQUIRED_CLAIMS)},
        )
    except jwt.PyJWTError as exc:
        raise DownstreamTokenRequestError('Invalid downstream token request JWT.') from exc
    scope = str(claims.get('scope') or '')
    if scope != DOWNSTREAM_TOKEN_SCOPE:
        raise DownstreamTokenRequestError('Downstream token request scope mismatch.')
    aud = claims.get('aud')
    if isinstance(aud, list):
        if DOWNSTREAM_TOKEN_AUDIENCE not in aud:
            raise DownstreamTokenRequestError('Downstream token request audience mismatch.')
    elif str(aud or '') != DOWNSTREAM_TOKEN_AUDIENCE:
        raise DownstreamTokenRequestError('Downstream token request audience mismatch.')
    _assert_lifetime_within_limit(claims)
    for name in _REQUIRED_CLAIMS:
        value = claims.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise DownstreamTokenRequestError(f'Missing required claim: {name}.')
    return dict(claims)
