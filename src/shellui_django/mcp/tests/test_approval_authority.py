"""Regional MCP authority: approval assertion optional claims and verification."""

from __future__ import annotations

import time
import unittest
import uuid

from shellui_django.mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    InternalAssertionError,
    build_mcp_approval_assertion,
    verify_rs256_mcp_assertion,
)
from shellui_django.mcp.tests.rs256_helpers import encode_test_rs256_jwt, generate_test_rsa_jwks

TEST_ISSUER = 'https://ai.example.com'
TEST_TARGET = 'https://identity.example.com/mcp'
GLOBAL_UUID = '550e8400-e29b-41d4-a716-446655440000'


class ApprovalAuthoritySignatureTests(unittest.TestCase):
    """Optional grant_version / global binding pair; strict validation."""

    @classmethod
    def setUpClass(cls):
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()

    def _verify(self, token: str):
        return verify_rs256_mcp_assertion(
            token,
            self.jwks,
            expected_issuer=TEST_ISSUER,
            expected_audience=APPROVAL_AUDIENCE,
            expected_scope=APPROVAL_SCOPE,
            expected_target=TEST_TARGET,
        )

    def test_grant_version_zero_personal_no_global_pair(self):
        token = build_mcp_approval_assertion(
            company_id=1,
            agent_id='a1',
            service='saas',
            action='t1',
            arguments_hash='abc',
            audience_url=TEST_TARGET,
            private_key_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            grant_version=0,
        )
        claims = self._verify(token)
        self.assertIn('grant_version', claims)
        self.assertEqual(claims['grant_version'], 0)
        self.assertNotIn('global_company_id', claims)
        self.assertNotIn('company_binding_version', claims)

    def test_delegated_global_pair_normalized_uuid(self):
        token = build_mcp_approval_assertion(
            company_id=10,
            agent_id='a1',
            service='saas',
            action='t1',
            arguments_hash='abc',
            audience_url=TEST_TARGET,
            private_key_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            global_company_id=GLOBAL_UUID.upper().replace('-', ''),
            company_binding_version=2,
            grant_version='v1',
        )
        claims = self._verify(token)
        self.assertEqual(claims['global_company_id'], GLOBAL_UUID)
        self.assertEqual(claims['company_binding_version'], 2)
        self.assertEqual(claims['grant_version'], 'v1')

    def test_incomplete_global_pair_rejected(self):
        with self.assertRaises(InternalAssertionError) as ctx:
            build_mcp_approval_assertion(
                company_id=1,
                agent_id='a1',
                service='saas',
                action='t1',
                arguments_hash='x',
                audience_url=TEST_TARGET,
                private_key_pem=self.private_pem,
                kid=self.kid,
                issuer=TEST_ISSUER,
                global_company_id=GLOBAL_UUID,
            )
        self.assertIn('both', str(ctx.exception).lower())

    def test_malformed_global_company_id_rejected(self):
        with self.assertRaises(InternalAssertionError):
            build_mcp_approval_assertion(
                company_id=1,
                agent_id='a1',
                service='saas',
                action='t1',
                arguments_hash='x',
                audience_url=TEST_TARGET,
                private_key_pem=self.private_pem,
                kid=self.kid,
                issuer=TEST_ISSUER,
                global_company_id='not-a-uuid',
                company_binding_version=0,
            )

    def test_company_binding_version_bool_rejected(self):
        with self.assertRaises(InternalAssertionError):
            build_mcp_approval_assertion(
                company_id=1,
                agent_id='a1',
                service='saas',
                action='t1',
                arguments_hash='x',
                audience_url=TEST_TARGET,
                private_key_pem=self.private_pem,
                kid=self.kid,
                issuer=TEST_ISSUER,
                global_company_id=GLOBAL_UUID,
                company_binding_version=True,  # type: ignore[arg-type]
            )

    def test_negative_company_id_rejected(self):
        with self.assertRaises(InternalAssertionError):
            build_mcp_approval_assertion(
                company_id=-1,
                agent_id='a1',
                service='saas',
                action='t1',
                arguments_hash='x',
                audience_url=TEST_TARGET,
                private_key_pem=self.private_pem,
                kid=self.kid,
                issuer=TEST_ISSUER,
            )


class ApprovalMalformedProofTests(unittest.TestCase):
    """Wrong signing key or truncated JWT must not verify as a valid proof."""

    @classmethod
    def setUpClass(cls):
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()
        cls.other_jwks, cls.other_private_pem, cls.other_kid = generate_test_rsa_jwks()

    def test_wrong_signing_key_rejected(self):
        now = int(time.time())
        claims = {
            'iss': TEST_ISSUER,
            'aud': APPROVAL_AUDIENCE,
            'sub': 'agent:a1',
            'scope': APPROVAL_SCOPE,
            'company_id': 1,
            'agent_id': 'a1',
            'service': 'saas',
            'action': 't1',
            'arguments_hash': 'abc',
            'target': TEST_TARGET,
            'grant_version': 0,
            'iat': now,
            'exp': now + 60,
            'jti': uuid.uuid4().hex,
        }
        token = encode_test_rs256_jwt(claims, private_pem=self.other_private_pem, kid=self.other_kid)
        with self.assertRaises(InternalAssertionError):
            verify_rs256_mcp_assertion(
                token,
                self.jwks,
                expected_issuer=TEST_ISSUER,
                expected_audience=APPROVAL_AUDIENCE,
                expected_scope=APPROVAL_SCOPE,
                expected_target=TEST_TARGET,
            )

    def test_truncated_jwt_rejected(self):
        token = build_mcp_approval_assertion(
            company_id=1,
            agent_id='a1',
            service='saas',
            action='t1',
            arguments_hash='abc',
            audience_url=TEST_TARGET,
            private_key_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            grant_version=0,
        )
        with self.assertRaises(InternalAssertionError):
            verify_rs256_mcp_assertion(
                token[:-5],
                self.jwks,
                expected_issuer=TEST_ISSUER,
                expected_audience=APPROVAL_AUDIENCE,
                expected_scope=APPROVAL_SCOPE,
                expected_target=TEST_TARGET,
            )
