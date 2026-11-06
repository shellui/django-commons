"""decode_identity_rs256_jwt: required core claims and strict timestamp types."""

from __future__ import annotations

import time
import unittest
import uuid

import jwt

from shellui_django.mcp.identity_jwks import IdentityJwksError, decode_identity_rs256_jwt
from shellui_django.mcp.tests.rs256_helpers import generate_test_rsa_jwks

TEST_ISSUER = 'https://identity.example.com'
TEST_AUD = 'shellui-mcp-revocation'


class IdentityJwksDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()

    def _claims(self, *, with_jti: bool, string_times: bool = False) -> dict:
        now = int(time.time())
        iat_v: int | str = f'{now}' if string_times else now
        exp_v: int | str = f'{now + 30}' if string_times else now + 30
        c = {
            'iss': TEST_ISSUER,
            'aud': TEST_AUD,
            'sub': 'identity',
            'scope': 'mcp.revocation.list',
            'iat': iat_v,
            'exp': exp_v,
        }
        if with_jti:
            c['jti'] = uuid.uuid4().hex
        return c

    def test_jti_always_required(self):
        claims = self._claims(with_jti=False)
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(IdentityJwksError):
            decode_identity_rs256_jwt(
                token,
                audience=TEST_AUD,
                issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_decodes_with_core_and_normalizes_string_timestamps(self):
        claims = self._claims(with_jti=True, string_times=True)
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        out = decode_identity_rs256_jwt(
            token,
            audience=TEST_AUD,
            issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertIsInstance(out['iat'], int)
        self.assertIsInstance(out['exp'], int)
        self.assertIn('jti', out)

    def test_empty_require_claims_still_requires_core_including_jti(self):
        claims = self._claims(with_jti=True)
        del claims['iat']
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(IdentityJwksError):
            decode_identity_rs256_jwt(
                token,
                audience=TEST_AUD,
                issuer=TEST_ISSUER,
                jwks=self.jwks,
                require_claims=(),
            )

    def test_extra_require_claims_merged(self):
        claims = self._claims(with_jti=True)
        claims['extra_policy'] = 'x'
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        out = decode_identity_rs256_jwt(
            token,
            audience=TEST_AUD,
            issuer=TEST_ISSUER,
            jwks=self.jwks,
            require_claims=('extra_policy',),
        )
        self.assertEqual(out.get('extra_policy'), 'x')

    def test_missing_extra_required_claim_fails_after_core_ok(self):
        claims = self._claims(with_jti=True)
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(IdentityJwksError):
            decode_identity_rs256_jwt(
                token,
                audience=TEST_AUD,
                issuer=TEST_ISSUER,
                jwks=self.jwks,
                require_claims=('extra_policy',),
            )
