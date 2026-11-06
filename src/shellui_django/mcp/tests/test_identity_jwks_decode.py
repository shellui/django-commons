"""decode_identity_rs256_jwt requires jti when caller passes require_claims including jti."""

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

    def _claims(self, *, with_jti: bool) -> dict:
        now = int(time.time())
        c = {
            'iss': TEST_ISSUER,
            'aud': TEST_AUD,
            'sub': 'identity',
            'scope': 'mcp.revocation.list',
            'iat': now,
            'exp': now + 30,
        }
        if with_jti:
            c['jti'] = uuid.uuid4().hex
        return c

    def test_jti_required_when_requested(self):
        claims = self._claims(with_jti=False)
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(IdentityJwksError):
            decode_identity_rs256_jwt(
                token,
                audience=TEST_AUD,
                issuer=TEST_ISSUER,
                jwks=self.jwks,
                require_claims=('exp', 'iat', 'sub', 'scope', 'jti'),
            )

    def test_jti_present_decodes(self):
        claims = self._claims(with_jti=True)
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        out = decode_identity_rs256_jwt(
            token,
            audience=TEST_AUD,
            issuer=TEST_ISSUER,
            jwks=self.jwks,
            require_claims=('exp', 'iat', 'sub', 'scope', 'jti'),
        )
        self.assertIn('jti', out)

    def test_empty_require_claims_still_requires_core(self):
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
