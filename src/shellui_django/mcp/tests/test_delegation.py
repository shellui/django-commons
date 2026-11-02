import time
import unittest
import uuid

import jwt
from cryptography.hazmat.primitives import serialization

from shellui_django.mcp.delegation import (
    DOWNSTREAM_TOKEN_AUDIENCE,
    DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS,
    DOWNSTREAM_TOKEN_SCOPE,
    DownstreamTokenRequestError,
    sign_downstream_token_request,
    verify_downstream_token_request,
)
from shellui_django.mcp.tests.rs256_helpers import generate_test_rsa_jwks

TEST_ISSUER = 'https://gateway.example.com'
TEST_RESOURCE = 'https://storage.example.com/mcp'


class DownstreamTokenDelegationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()
        cls.public_pem = (
            serialization.load_pem_private_key(cls.private_pem.encode(), password=None)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def _sign(self, **kwargs):
        defaults = {
            'private_key_pem': self.private_pem,
            'kid': self.kid,
            'issuer': TEST_ISSUER,
            'agent_id': 'agent-abc',
            'company_id': 42,
            'resource': TEST_RESOURCE,
            'ttl': 30,
        }
        defaults.update(kwargs)
        return sign_downstream_token_request(**defaults)

    def _verify(self, token: str, *, jwks_or_pem=None, issuer=TEST_ISSUER):
        material = jwks_or_pem if jwks_or_pem is not None else self.jwks
        return verify_downstream_token_request(token, material, issuer)

    def test_sign_verify_round_trip_jwks(self):
        token = self._sign()
        claims = self._verify(token)
        self.assertEqual(claims['iss'], TEST_ISSUER)
        self.assertEqual(claims['aud'], DOWNSTREAM_TOKEN_AUDIENCE)
        self.assertEqual(claims['scope'], DOWNSTREAM_TOKEN_SCOPE)
        self.assertEqual(claims['agent_id'], 'agent-abc')
        self.assertEqual(claims['company_id'], 42)
        self.assertEqual(claims['resource'], TEST_RESOURCE)
        self.assertTrue(claims['jti'])
        self.assertLessEqual(int(claims['exp']) - int(claims['iat']), DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS)

    def test_sign_verify_round_trip_public_pem(self):
        token = self._sign(ttl=60)
        claims = self._verify(token, jwks_or_pem=self.public_pem)
        self.assertEqual(claims['resource'], TEST_RESOURCE)

    def test_bearer_prefix_accepted(self):
        token = self._sign()
        claims = self._verify(f'Bearer {token}')
        self.assertEqual(claims['agent_id'], 'agent-abc')

    def test_sign_rejects_ttl_over_max(self):
        with self.assertRaises(DownstreamTokenRequestError):
            self._sign(ttl=61)

    def test_sign_rejects_zero_ttl(self):
        with self.assertRaises(DownstreamTokenRequestError):
            self._sign(ttl=0)

    def test_verify_rejects_lifetime_longer_than_max(self):
        now = int(time.time())
        claims = {
            'iss': TEST_ISSUER,
            'aud': DOWNSTREAM_TOKEN_AUDIENCE,
            'scope': DOWNSTREAM_TOKEN_SCOPE,
            'agent_id': 'agent-abc',
            'company_id': 42,
            'resource': TEST_RESOURCE,
            'jti': uuid.uuid4().hex,
            'iat': now,
            'exp': now + DOWNSTREAM_TOKEN_REQUEST_MAX_LIFETIME_SECONDS + 10,
        }
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(DownstreamTokenRequestError) as ctx:
            self._verify(token)
        self.assertIn('lifetime', str(ctx.exception).lower())

    def test_verify_rejects_expired(self):
        now = int(time.time())
        claims = {
            'iss': TEST_ISSUER,
            'aud': DOWNSTREAM_TOKEN_AUDIENCE,
            'scope': DOWNSTREAM_TOKEN_SCOPE,
            'agent_id': 'agent-abc',
            'company_id': 42,
            'resource': TEST_RESOURCE,
            'jti': uuid.uuid4().hex,
            'iat': now - 30,
            'exp': now - 10,
        }
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(DownstreamTokenRequestError):
            self._verify(token)

    def test_verify_rejects_wrong_audience(self):
        now = int(time.time())
        claims = {
            'iss': TEST_ISSUER,
            'aud': 'wrong-audience',
            'scope': DOWNSTREAM_TOKEN_SCOPE,
            'agent_id': 'agent-abc',
            'company_id': 42,
            'resource': TEST_RESOURCE,
            'jti': uuid.uuid4().hex,
            'iat': now,
            'exp': now + 30,
        }
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(DownstreamTokenRequestError):
            self._verify(token)

    def test_verify_rejects_wrong_issuer(self):
        token = self._sign()
        with self.assertRaises(DownstreamTokenRequestError):
            self._verify(token, issuer='https://other.example.com')

    def test_verify_rejects_wrong_scope(self):
        now = int(time.time())
        claims = {
            'iss': TEST_ISSUER,
            'aud': DOWNSTREAM_TOKEN_AUDIENCE,
            'scope': 'mcp.other.scope',
            'agent_id': 'agent-abc',
            'company_id': 42,
            'resource': TEST_RESOURCE,
            'jti': uuid.uuid4().hex,
            'iat': now,
            'exp': now + 30,
        }
        token = jwt.encode(claims, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
        token = token.decode('utf-8') if isinstance(token, bytes) else token
        with self.assertRaises(DownstreamTokenRequestError) as ctx:
            self._verify(token)
        self.assertIn('scope', str(ctx.exception).lower())

    def test_verify_rejects_missing_claims(self):
        token = self._sign()
        payload = jwt.decode(token, options={'verify_signature': False})
        for key in ('agent_id', 'company_id', 'resource', 'jti'):
            tampered = dict(payload)
            tampered.pop(key)
            bad = jwt.encode(tampered, self.private_pem, algorithm='RS256', headers={'kid': self.kid})
            bad = bad.decode('utf-8') if isinstance(bad, bytes) else bad
            with self.assertRaises(DownstreamTokenRequestError):
                self._verify(bad)

    def test_verify_rejects_hs256_alg_confusion(self):
        now = int(time.time())
        hs256_token = jwt.encode(
            {
                'iss': TEST_ISSUER,
                'aud': DOWNSTREAM_TOKEN_AUDIENCE,
                'scope': DOWNSTREAM_TOKEN_SCOPE,
                'agent_id': 'agent-abc',
                'company_id': 42,
                'resource': TEST_RESOURCE,
                'jti': uuid.uuid4().hex,
                'iat': now,
                'exp': now + 30,
            },
            'symmetric-test-secret-for-hs256-rejection',
            algorithm='HS256',
        )
        hs256_token = hs256_token.decode('utf-8') if isinstance(hs256_token, bytes) else hs256_token
        with self.assertRaises(DownstreamTokenRequestError) as ctx:
            self._verify(hs256_token)
        self.assertIn('RS256', str(ctx.exception))

    def test_verify_rejects_none_algorithm(self):
        now = int(time.time())
        header = {'alg': 'none', 'typ': 'JWT'}
        payload = {
            'iss': TEST_ISSUER,
            'aud': DOWNSTREAM_TOKEN_AUDIENCE,
            'scope': DOWNSTREAM_TOKEN_SCOPE,
            'agent_id': 'agent-abc',
            'company_id': 42,
            'resource': TEST_RESOURCE,
            'jti': uuid.uuid4().hex,
            'iat': now,
            'exp': now + 30,
        }
        none_token = jwt.encode(payload, '', algorithm='none', headers=header)
        none_token = none_token.decode('utf-8') if isinstance(none_token, bytes) else none_token
        with self.assertRaises(DownstreamTokenRequestError) as ctx:
            self._verify(none_token)
        self.assertIn('RS256', str(ctx.exception))

    def test_verify_rejects_wrong_signing_key(self):
        _other_jwks, other_private, other_kid = generate_test_rsa_jwks()
        token = sign_downstream_token_request(
            other_private,
            other_kid,
            TEST_ISSUER,
            'agent-abc',
            42,
            TEST_RESOURCE,
            30,
        )
        with self.assertRaises(DownstreamTokenRequestError):
            self._verify(token)
