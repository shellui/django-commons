"""JWKS fetch: configured URL only, no redirects, size cap, timeout."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from django.test import SimpleTestCase, override_settings

from shellui_django.mcp.identity_jwks import (
    JWKS_MAX_RESPONSE_BYTES,
    IdentityJwksError,
    _jwks_cache,
    get_jwks_document,
)


class _JwksServer(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        host, port = self.server.server_address
        if self.path.startswith('/redirect'):
            location = f'http://{host}:{port}/jwks.json'
            body = b''
            status = 302
            extra = {'Location': location}
        elif self.path.startswith('/large'):
            body = b'{"keys":[]}' + (b' ' * (JWKS_MAX_RESPONSE_BYTES + 8))
            status = 200
            extra = {'Content-Type': 'application/json'}
        elif self.path.startswith('/slow'):
            import time

            time.sleep(1.5)
            body = b'{"keys":[]}'
            status = 200
            extra = {'Content-Type': 'application/json'}
        else:
            body = b'{"keys":[]}'
            status = 200
            extra = {'Content-Type': 'application/json'}
        self.send_response(status)
        for key, value in extra.items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, fmt, *args):
        return


@override_settings(DEBUG=True)
class IdentityJwksFetchTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), _JwksServer)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.httpd.server_address
        cls.base = f'http://{host}:{port}'

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.thread.join(timeout=2)
        cls.httpd.server_close()
        super().tearDownClass()

    def setUp(self):
        _jwks_cache.clear()

    def test_fetches_configured_url(self):
        document = get_jwks_document(jwks_url=f'{self.base}/jwks.json', timeout=2)
        self.assertEqual(document, {'keys': []})

    def test_redirect_is_not_followed(self):
        with self.assertRaises(IdentityJwksError) as ctx:
            get_jwks_document(jwks_url=f'{self.base}/redirect', timeout=2)
        self.assertIn('redirect', str(ctx.exception).lower())

    def test_response_over_size_cap_is_rejected(self):
        with self.assertRaises(IdentityJwksError) as ctx:
            get_jwks_document(jwks_url=f'{self.base}/large', timeout=2)
        self.assertIn('too large', str(ctx.exception).lower())

    def test_timeout_is_applied(self):
        with self.assertRaises(IdentityJwksError):
            get_jwks_document(jwks_url=f'{self.base}/slow', timeout=0.2)

    def test_non_positive_timeout_is_rejected(self):
        with self.assertRaises(IdentityJwksError) as ctx:
            get_jwks_document(jwks_url='http://127.0.0.1:9/jwks.json', timeout=0)
        self.assertIn('timeout', str(ctx.exception).lower())

    def test_non_http_url_is_rejected(self):
        with self.assertRaises(IdentityJwksError) as ctx:
            get_jwks_document(jwks_url='file:///no-such-jwks.json', timeout=1)
        self.assertIn('invalid', str(ctx.exception).lower())

    @override_settings(DEBUG=False)
    def test_http_url_requires_https_when_debug_is_off(self):
        with self.assertRaises(IdentityJwksError) as ctx:
            get_jwks_document(jwks_url=f'{self.base}/jwks.json', timeout=1)
        self.assertIn('https', str(ctx.exception).lower())
