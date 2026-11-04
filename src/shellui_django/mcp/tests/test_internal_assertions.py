import time
import unittest
import uuid

import jwt
from cryptography.hazmat.primitives import serialization

from shellui_django.mcp.internal import (
    CALL_LOG_AUDIENCE,
    CALL_LOG_SCOPE,
    INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS,
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    InternalAssertionError,
    build_mcp_call_log_assertion,
    build_mcp_revocation_assertion,
    verify_mcp_internal_assertion,
    verify_rs256_mcp_assertion,
)
from shellui_django.mcp.tests.rs256_helpers import generate_test_rsa_jwks

TEST_ISSUER = 'https://ai.example.com'
TEST_TARGET = 'https://identity.example.com'
OTHER_ISSUER = 'https://other.example.com'


class InternalAssertionRs256Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()
        cls.other_jwks, cls.other_private_pem, cls.other_kid = generate_test_rsa_jwks()
        cls.public_pem = (
            serialization.load_pem_private_key(cls.private_pem.encode(), password=None)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def _sign_revocation(self, **kwargs):
        defaults = {
            'audience_url': TEST_TARGET,
            'private_key_pem': self.private_pem,
            'kid': self.kid,
            'issuer': TEST_ISSUER,
        }
        defaults.update(kwargs)
        return build_mcp_revocation_assertion(**defaults)

    def _verify(self, token: str, *, jwks_or_pem=None, issuer=TEST_ISSUER):
        material = jwks_or_pem if jwks_or_pem is not None else self.jwks
        return verify_mcp_internal_assertion(
            token,
            material,
            expected_issuer=issuer,
            expected_audience=REVOCATION_AUDIENCE,
            expected_scope=REVOCATION_SCOPE,
            expected_target=TEST_TARGET,
        )

    def test_valid_round_trip(self):
        token = self._sign_revocation()
        claims = self._verify(token)
        self.assertEqual(claims['iss'], TEST_ISSUER)
        self.assertEqual(claims['sub'], 'service')
        self.assertLessEqual(int(claims['exp']) - int(claims['iat']), INTERNAL_ASSERTION_MAX_LIFETIME_SECONDS)

    def test_call_log_round_trip(self):
        token = build_mcp_call_log_assertion(
            audience_url=TEST_TARGET,
            private_key_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
        )
        claims = verify_rs256_mcp_assertion(
            token,
            self.jwks,
            expected_issuer=TEST_ISSUER,
            expected_audience=CALL_LOG_AUDIENCE,
            expected_scope=CALL_LOG_SCOPE,
            expected_target=TEST_TARGET,
        )
        self.assertEqual(claims['scope'], CALL_LOG_SCOPE)

    def test_wrong_verification_key(self):
        token = self._sign_revocation()
        with self.assertRaises(InternalAssertionError):
            self._verify(token, jwks_or_pem=self.other_jwks)

    def test_wrong_issuer(self):
        token = self._sign_revocation()
        with self.assertRaises(InternalAssertionError):
            self._verify(token, issuer=OTHER_ISSUER)

    def test_hs256_rejected(self):
        now = int(time.time())
        hs256_token = jwt.encode(
            {
                'iss': TEST_ISSUER,
                'aud': REVOCATION_AUDIENCE,
                'sub': 'service',
                'scope': REVOCATION_SCOPE,
                'target': TEST_TARGET,
                'iat': now,
                'exp': now + 60,
                'jti': uuid.uuid4().hex,
            },
            'shared-secret',
            algorithm='HS256',
        )
        hs256_token = hs256_token.decode('utf-8') if isinstance(hs256_token, bytes) else hs256_token
        with self.assertRaises(InternalAssertionError) as ctx:
            self._verify(hs256_token)
        self.assertIn('RS256', str(ctx.exception))

    def test_alg_none_rejected(self):
        now = int(time.time())
        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {
            'iss': TEST_ISSUER,
            'aud': REVOCATION_AUDIENCE,
            'sub': 'service',
            'scope': REVOCATION_SCOPE,
            'target': TEST_TARGET,
            'iat': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
        }
        import base64
        import json

        def b64(data):
            return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()

        token = f'{b64(header)}.{b64(payload)}.'
        with self.assertRaises(InternalAssertionError):
            self._verify(token)

    def test_expired_rejected(self):
        now = int(time.time())
        claims = {
            'iss': TEST_ISSUER,
            'aud': REVOCATION_AUDIENCE,
            'sub': 'service',
            'scope': REVOCATION_SCOPE,
            'target': TEST_TARGET,
            'iat': now - 120,
            'exp': now - 60,
            'jti': uuid.uuid4().hex,
        }
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(InternalAssertionError):
            self._verify(token)

    def test_wrong_audience(self):
        token = self._sign_revocation()
        with self.assertRaises(InternalAssertionError):
            verify_mcp_internal_assertion(
                token,
                self.jwks,
                expected_issuer=TEST_ISSUER,
                expected_audience='wrong-audience',
                expected_scope=REVOCATION_SCOPE,
                expected_target=TEST_TARGET,
            )

    def test_wrong_scope(self):
        token = self._sign_revocation()
        with self.assertRaises(InternalAssertionError):
            verify_mcp_internal_assertion(
                token,
                self.jwks,
                expected_issuer=TEST_ISSUER,
                expected_audience=REVOCATION_AUDIENCE,
                expected_scope='wrong.scope',
                expected_target=TEST_TARGET,
            )

    def test_wrong_target(self):
        token = self._sign_revocation()
        with self.assertRaises(InternalAssertionError):
            verify_mcp_internal_assertion(
                token,
                self.jwks,
                expected_issuer=TEST_ISSUER,
                expected_audience=REVOCATION_AUDIENCE,
                expected_scope=REVOCATION_SCOPE,
                expected_target='https://evil.example.com',
            )

    def test_jti_replay_rejected(self):
        token = self._sign_revocation()
        seen: set[str] = set()

        def register(jti: str) -> bool:
            if jti in seen:
                return False
            seen.add(jti)
            return True

        verify_mcp_internal_assertion(
            token,
            self.jwks,
            expected_issuer=TEST_ISSUER,
            expected_audience=REVOCATION_AUDIENCE,
            expected_scope=REVOCATION_SCOPE,
            expected_target=TEST_TARGET,
            register_jti=register,
        )
        with self.assertRaises(InternalAssertionError) as ctx:
            verify_mcp_internal_assertion(
                token,
                self.jwks,
                expected_issuer=TEST_ISSUER,
                expected_audience=REVOCATION_AUDIENCE,
                expected_scope=REVOCATION_SCOPE,
                expected_target=TEST_TARGET,
                register_jti=register,
            )
        self.assertIn('replay', str(ctx.exception).lower())

    def test_public_pem_verification(self):
        token = self._sign_revocation()
        claims = self._verify(token, jwks_or_pem=self.public_pem)
        self.assertEqual(claims['iss'], TEST_ISSUER)
