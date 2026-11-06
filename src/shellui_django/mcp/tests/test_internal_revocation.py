import hashlib
import json
import time
import unittest
import uuid

import jwt

from shellui_django.mcp.internal import (
    REVOCATION_AUDIENCE,
    REVOCATION_CACHE_SECONDS,
    REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS,
    REVOCATION_LIST_SCOPE,
    InternalAssertionError,
    build_mcp_revocation_list_response_assertion,
    parse_trusted_revocation_poll_response,
    verify_mcp_revocation_list_response,
)
from shellui_django.mcp.tests.rs256_helpers import generate_test_rsa_jwks, sign_test_revocation_list_assertion

TEST_ISSUER = 'https://identity.example.com'
GLOBAL_CO = '550e8400-e29b-41d4-a716-446655440000'


def _auth_fingerprint(*, global_company_id: str, company_binding_version: int, grant_version: int) -> str:
    payload = {
        'company_binding_version': company_binding_version,
        'global_company_id': global_company_id,
        'grant_version': grant_version,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class RevocationListJwksVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()

    def _signed_payload(self, *, ids=None, agents=None):
        ids = ids if ids is not None else ['agent-1']
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=ids,
            agents=agents or [],
            cache_seconds=REVOCATION_CACHE_SECONDS,
        )
        return {
            'revoked_agent_ids': ids,
            'agents': agents or [],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_assertion': assertion,
        }

    def test_verify_accepts_matching_payload(self):
        agents = [{'agent_id': 'a', 'company_id': 1, 'is_active': False, 'paused': True}]
        payload = self._signed_payload(ids=['a', 'b'], agents=agents)
        trusted = verify_mcp_revocation_list_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(trusted['revoked_agent_ids'], ['a', 'b'])
        self.assertIsNone(trusted.get('revocation_policy_version'))
        self.assertIsNone(trusted.get('max_active_grant_version'))
        for row in trusted['agents']:
            self.assertIn('mcp_authority_snapshot_fingerprint', row)
            self.assertIsNone(row['mcp_authority_snapshot_fingerprint'])
        ids, cache, rows = parse_trusted_revocation_poll_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(ids, frozenset({'a', 'b'}))
        self.assertEqual(cache, REVOCATION_CACHE_SECONDS)
        self.assertEqual(len(rows), len(agents))
        self.assertEqual({r['agent_id'] for r in rows}, {'a'})
        for r in rows:
            self.assertIsNone(r['mcp_authority_snapshot_fingerprint'])

    def test_missing_assertion_fails_closed(self):
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                {'revoked_agent_ids': []},
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_body_tamper_fails_closed(self):
        payload = self._signed_payload(ids=['a'])
        payload['revoked_agent_ids'] = ['b']
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_unsigned_envelope_when_signed_claim_has_policy_version(self):
        agents = []
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=agents,
            revocation_policy_version=0,
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_assertion': assertion,
        }
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_hs256_assertion_rejected(self):
        now = int(time.time())
        hs256_token = jwt.encode(
            {
                'iss': TEST_ISSUER,
                'aud': REVOCATION_AUDIENCE,
                'sub': 'identity',
                'scope': REVOCATION_LIST_SCOPE,
                'revoked_agent_ids': ['a'],
                'agents': [],
                'cache_seconds': REVOCATION_CACHE_SECONDS,
                'iat': now,
                'exp': now + REVOCATION_CACHE_SECONDS,
                'jti': uuid.uuid4().hex,
            },
            'test-hs256-secret',
            algorithm='HS256',
        )
        hs256_token = hs256_token.decode('utf-8') if isinstance(hs256_token, bytes) else hs256_token
        payload = {
            'revoked_agent_ids': ['a'],
            'agents': [],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_assertion': hs256_token,
        }
        with self.assertRaises(InternalAssertionError) as ctx:
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )
        self.assertIn('RS256', str(ctx.exception))

    def test_optional_policy_and_grant_versions_in_body_and_return(self):
        agents = [{'agent_id': 'a', 'company_id': 1}]
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=['a'],
            agents=agents,
            cache_seconds=REVOCATION_CACHE_SECONDS,
            revocation_policy_version=0,
            max_active_grant_version=7,
        )
        payload = {
            'revoked_agent_ids': ['a'],
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_policy_version': 0,
            'max_active_grant_version': 7,
            'revocation_assertion': assertion,
        }
        trusted = verify_mcp_revocation_list_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(trusted['revocation_policy_version'], 0)
        self.assertEqual(trusted['max_active_grant_version'], 7)
        ids, cache, rows = parse_trusted_revocation_poll_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(ids, frozenset({'a'}))
        self.assertEqual(cache, REVOCATION_CACHE_SECONDS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['agent_id'], 'a')
        self.assertEqual(rows[0]['company_id'], 1)
        self.assertIsNone(rows[0]['mcp_authority_snapshot_fingerprint'])

    def test_body_version_mismatch_fails_closed(self):
        agents = []
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=agents,
            revocation_policy_version=1,
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_policy_version': 2,
            'revocation_assertion': assertion,
        }
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_body_string_zero_matches_signed_int_zero(self):
        agents = []
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=agents,
            revocation_policy_version=0,
            max_active_grant_version=0,
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_policy_version': '0',
            'max_active_grant_version': '0',
            'revocation_assertion': assertion,
        }
        trusted = verify_mcp_revocation_list_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(trusted['revocation_policy_version'], 0)
        self.assertEqual(trusted['max_active_grant_version'], 0)

    def test_unsigned_body_max_active_grant_when_absent_in_jwt(self):
        agents = []
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=agents,
            revocation_policy_version=0,
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_policy_version': 0,
            'max_active_grant_version': 1,
            'revocation_assertion': assertion,
        }
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_parse_tuple_raises_on_malicious_body(self):
        agents = []
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=['x'],
            agents=agents,
            revocation_policy_version=0,
        )
        payload = {
            'revoked_agent_ids': ['x'],
            'agents': agents,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_policy_version': 9,
            'revocation_assertion': assertion,
        }
        with self.assertRaises(InternalAssertionError):
            parse_trusted_revocation_poll_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_builder_rejects_excessive_lifetime(self):
        with self.assertRaises(InternalAssertionError):
            build_mcp_revocation_list_response_assertion(
                revoked_agent_ids=[],
                lifetime_seconds=REVOCATION_LIST_MAX_ASSERTION_LIFETIME_SECONDS + 1,
            )

    def test_delegated_agent_row_fingerprint_and_cap(self):
        row = {
            'agent_id': 'd1',
            'company_id': 9,
            'global_company_id': GLOBAL_CO.upper().replace('-', ''),
            'company_binding_version': 0,
            'grant_version': 2,
        }
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=[row],
            max_active_grant_version=2,
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': [row],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'max_active_grant_version': 2,
            'revocation_assertion': assertion,
        }
        trusted = verify_mcp_revocation_list_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        out_row = trusted['agents'][0]
        self.assertEqual(out_row['global_company_id'], GLOBAL_CO)
        self.assertEqual(out_row['company_binding_version'], 0)
        self.assertEqual(out_row['grant_version'], 2)
        self.assertEqual(
            out_row['mcp_authority_snapshot_fingerprint'],
            _auth_fingerprint(
                global_company_id=GLOBAL_CO,
                company_binding_version=0,
                grant_version=2,
            ),
        )

    def test_incomplete_delegated_pair_in_row_rejected(self):
        row = {'agent_id': 'x', 'global_company_id': GLOBAL_CO}
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=[row],
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': [row],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_assertion': assertion,
        }
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_grant_exceeds_signed_cap(self):
        row = {
            'agent_id': 'd1',
            'global_company_id': GLOBAL_CO,
            'company_binding_version': 1,
            'grant_version': 3,
        }
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=[row],
            max_active_grant_version=2,
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': [row],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'max_active_grant_version': 2,
            'revocation_assertion': assertion,
        }
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_personal_grant_version_zero_allowed(self):
        row = {'agent_id': 'p1', 'company_id': 1, 'grant_version': 0}
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=[],
            agents=[row],
            max_active_grant_version=0,
        )
        payload = {
            'revoked_agent_ids': [],
            'agents': [row],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'max_active_grant_version': 0,
            'revocation_assertion': assertion,
        }
        trusted = verify_mcp_revocation_list_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(trusted['agents'][0]['grant_version'], 0)
        self.assertIsNone(trusted['agents'][0]['mcp_authority_snapshot_fingerprint'])
