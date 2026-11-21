"""Thread-safe Identity JWKS fetch and RS256 JWT verification (no SimpleJWT)."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

import jwt
from jwt.algorithms import RSAAlgorithm

_CACHE_TTL_SECONDS = 300
# Match ``INTERNAL_ASSERTION_LEEWAY_SECONDS`` in ``internal`` for Identity JWT verification.
IDENTITY_RS256_LEEWAY_SECONDS = 5
JWKS_MAX_RESPONSE_BYTES = 256 * 1024
_DEFAULT_JWKS_TIMEOUT_SECONDS = 10.0
_cache_lock = threading.Lock()
_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}


class IdentityJwksError(Exception):
    pass


def jwt_unix_timestamp_claim_strict(value: Any, *, field: str) -> int:
    """``iat`` / ``exp`` after JWT decode: non-negative int, or digit-only string (PyJWT quirk).

    Rejects bool, float, and non-digit strings so values are not confused via ``int()`` coercion.
    """
    if isinstance(value, bool):
        raise IdentityJwksError(f'{field} must be a Unix timestamp.')
    if isinstance(value, float):
        raise IdentityJwksError(f'{field} must be a Unix timestamp.')
    if isinstance(value, int):
        if value < 0:
            raise IdentityJwksError(f'{field} must be non-negative.')
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s or not s.isdigit():
            raise IdentityJwksError(f'{field} must be a Unix timestamp.')
        return int(s)
    raise IdentityJwksError(f'{field} must be a Unix timestamp.')


def identity_jwks_url_for_issuer(issuer: str) -> str:
    base = (issuer or '').strip().rstrip('/')
    if not base:
        raise IdentityJwksError('Identity issuer is required.')
    return f'{base}/.well-known/jwks.json'


def _allow_insecure_jwks_url() -> bool:
    """``http`` JWKS URLs are accepted only when Django ``DEBUG`` is on."""
    try:
        from django.conf import settings

        return bool(settings.DEBUG)
    except Exception:
        return False


def _validated_jwks_url(url: str) -> str:
    """Return ``url`` when it is the exact document to fetch."""
    raw = (url or '').strip()
    if not raw or any(char in raw for char in ('\r', '\n', '\t', ' ')):
        raise IdentityJwksError('Identity JWKS URL is invalid.')
    parsed = urlsplit(raw)
    if parsed.username or parsed.password or parsed.fragment:
        raise IdentityJwksError('Identity JWKS URL is invalid.')
    if not parsed.hostname or not parsed.netloc:
        raise IdentityJwksError('Identity JWKS URL is invalid.')
    if parsed.scheme == 'https':
        return raw
    if parsed.scheme == 'http' and _allow_insecure_jwks_url():
        return raw
    if parsed.scheme == 'http':
        raise IdentityJwksError('Identity JWKS URL must use https.')
    raise IdentityJwksError('Identity JWKS URL is invalid.')


def _positive_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise IdentityJwksError('Identity JWKS timeout is required.')
    if timeout <= 0:
        raise IdentityJwksError('Identity JWKS timeout is required.')
    return float(timeout)


def _jwks_opener() -> urllib.request.OpenerDirector:
    """HTTP(S) opener that does not follow redirects or local URL schemes."""
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    return opener


def _fetch_jwks_document(url: str, *, timeout: float) -> dict[str, Any]:
    fetch_url = _validated_jwks_url(url)
    timeout_s = _positive_timeout(timeout)
    request = urllib.request.Request(fetch_url, headers={'Accept': 'application/json'})
    try:
        response = _jwks_opener().open(request, timeout=timeout_s)
    except urllib.error.HTTPError as exc:
        if 300 <= int(getattr(exc, 'code', 0) or 0) < 400:
            raise IdentityJwksError('Identity JWKS redirects are not allowed.') from exc
        raise IdentityJwksError('Failed to fetch Identity JWKS.') from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise IdentityJwksError('Failed to fetch Identity JWKS.') from exc
    with response:
        final_url = response.geturl()
        if urlsplit(final_url) != urlsplit(fetch_url):
            raise IdentityJwksError('Identity JWKS redirects are not allowed.')
        declared = response.headers.get('Content-Length')
        if declared is not None:
            try:
                if int(declared) > JWKS_MAX_RESPONSE_BYTES:
                    raise IdentityJwksError('Identity JWKS response is too large.')
            except ValueError as exc:
                raise IdentityJwksError('Identity JWKS response is too large.') from exc
        raw = response.read(JWKS_MAX_RESPONSE_BYTES + 1)
    if len(raw) > JWKS_MAX_RESPONSE_BYTES:
        raise IdentityJwksError('Identity JWKS response is too large.')
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityJwksError('Identity JWKS response was not JSON.') from exc
    if not isinstance(document, dict) or not isinstance(document.get('keys'), list):
        raise IdentityJwksError('Identity JWKS document is invalid.')
    return document


def get_jwks_document(*, jwks_url: str | None = None, jwks: dict[str, Any] | None = None, timeout: float = _DEFAULT_JWKS_TIMEOUT_SECONDS) -> dict[str, Any]:
    if jwks is not None:
        if not isinstance(jwks.get('keys'), list):
            raise IdentityJwksError('Inline JWKS document is invalid.')
        return jwks
    if not jwks_url:
        raise IdentityJwksError('identity_jwks_url or jwks is required.')
    now = time.monotonic()
    with _cache_lock:
        cached = _jwks_cache.get(jwks_url)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return cached[1]
    document = _fetch_jwks_document(jwks_url, timeout=timeout)
    with _cache_lock:
        _jwks_cache[jwks_url] = (now, document)
    return document


def _public_key_from_jwk(jwk: dict[str, Any]):
    if jwk.get('kty') != 'RSA':
        raise IdentityJwksError('Unsupported JWK type.')
    return RSAAlgorithm.from_jwk(json.dumps(jwk))


def resolve_public_verification_key(token: str, public_jwks_or_pem: dict[str, Any] | str):
    """Return a verification key from inline JWKS, a fetched document, or a PEM string."""
    if isinstance(public_jwks_or_pem, str):
        pem = public_jwks_or_pem.strip()
        if not pem:
            raise IdentityJwksError('Verification key is required.')
        return pem
    if isinstance(public_jwks_or_pem, dict):
        return resolve_verification_key(token, public_jwks_or_pem)
    raise IdentityJwksError('public_jwks_or_pem must be a PEM string or JWKS document.')


def resolve_verification_key(token: str, jwks_document: dict[str, Any]):
    header = jwt.get_unverified_header(token)
    kid = header.get('kid')
    keys = jwks_document.get('keys') or []
    candidates = [item for item in keys if isinstance(item, dict)]
    if kid:
        for jwk in candidates:
            if jwk.get('kid') == kid:
                return _public_key_from_jwk(jwk)
    if len(candidates) == 1:
        return _public_key_from_jwk(candidates[0])
    raise IdentityJwksError('No matching JWKS key for revocation assertion.')


def decode_identity_rs256_jwt(
    token: str,
    *,
    audience: str,
    issuer: str,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    timeout: float = 10.0,
    require_claims: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Verify an Identity-issued RS256 JWT against JWKS.

    Always requires ``exp``, ``iat``, ``sub``, ``scope``, and ``jti``. Names in
    ``require_claims`` add further required claims (union, never a substitute).
    Timestamp claims are normalized to strict non-negative integers after decode.
    """
    header = jwt.get_unverified_header(token)
    if header.get('alg') != 'RS256':
        raise IdentityJwksError('Identity JWT must use RS256.')
    document = get_jwks_document(jwks_url=jwks_url, jwks=jwks, timeout=timeout)
    key = resolve_verification_key(token, document)
    mandatory = {'exp', 'iat', 'sub', 'scope', 'jti'}
    merged = sorted(mandatory.union(require_claims))
    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=['RS256'],
            audience=audience,
            issuer=issuer,
            leeway=IDENTITY_RS256_LEEWAY_SECONDS,
            options={'require': merged},
        )
    except jwt.PyJWTError as exc:
        raise IdentityJwksError('Invalid Identity JWT.') from exc
    try:
        claims['iat'] = jwt_unix_timestamp_claim_strict(claims['iat'], field='iat')
        claims['exp'] = jwt_unix_timestamp_claim_strict(claims['exp'], field='exp')
    except KeyError as exc:
        raise IdentityJwksError('Invalid Identity JWT.') from exc
    return claims
