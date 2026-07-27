# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for OAuth 2.0 callback server functionality"""

import datetime as dt
import socket
import ssl
import threading
from http import HTTPStatus
from http.server import HTTPServer
from io import BytesIO
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import pytest

from workday_ldq.callback_server import (
    _validate_redirect_url,
    get_ssl_context,
    make_callback_handler,
    start_callback_server,
)


def _free_port() -> int:
    """Find an unused localhost port for a test-only server to bind to."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _start_server_on_free_port(scheme: str) -> HTTPServer:
    """Start a callback server, retrying on a rare port-collision race in _free_port()."""
    last_error = None
    for _ in range(5):
        port = _free_port()
        try:
            return start_callback_server(
                f"{scheme}://localhost:{port}/callback", "state123", threading.Event(), {},
            )
        except OSError as e:
            last_error = e
    raise last_error


# ---------------------------------------------------------------------------
# get_ssl_context
# ---------------------------------------------------------------------------

class TestGetSslContext:
    def setup_method(self):
        """Reset the singleton before each test."""
        import workday_ldq.callback_server as cb
        cb._ssl_context_cache = None
        cb._ssl_context_expiry = None

    def test_returns_ssl_context(self):
        ctx = get_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_returns_same_instance_on_second_call(self):
        ctx1 = get_ssl_context()
        ctx2 = get_ssl_context()
        assert ctx1 is ctx2

    def test_recreates_context_when_near_expiry(self):
        import workday_ldq.callback_server as cb
        ctx1 = get_ssl_context()
        # Wind expiry back so the cert is within the refresh buffer
        cb._ssl_context_expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60)
        ctx2 = get_ssl_context()
        assert ctx2 is not ctx1

    def test_does_not_recreate_when_expiry_is_far(self):
        import workday_ldq.callback_server as cb
        ctx1 = get_ssl_context()
        # Expiry is well beyond the buffer — should reuse
        cb._ssl_context_expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=23)
        ctx2 = get_ssl_context()
        assert ctx2 is ctx1

    def test_concurrent_calls_create_context_once(self):
        import workday_ldq.callback_server as cb
        create_count = {"count": 0}
        original_create = cb._create_ssl_context

        def counting_create():
            create_count["count"] += 1
            return original_create()

        results = []
        with patch.object(cb, "_create_ssl_context", side_effect=counting_create):
            threads = [threading.Thread(target=lambda: results.append(get_ssl_context()))
                       for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert create_count["count"] == 1
        assert all(ctx is results[0] for ctx in results)


# ---------------------------------------------------------------------------
# Callback handler
# ---------------------------------------------------------------------------

class TestCallbackHandler:
    def test_valid_callback_sets_code(self):
        result: dict = {}
        event = threading.Event()
        HandlerClass = make_callback_handler("state123", "/callback", event, result)

        instance = HandlerClass.__new__(HandlerClass)
        instance.path = "/callback?code=authcode&state=state123"
        instance.send_response = Mock()
        instance.send_header = Mock()
        instance.end_headers = Mock()
        instance.wfile = BytesIO()

        instance.do_GET()

        assert result.get("code") == "authcode"
        assert "error" not in result
        assert event.is_set()

    def test_state_mismatch_sets_error(self):
        result: dict = {}
        event = threading.Event()
        HandlerClass = make_callback_handler("expected_state", "/callback", event, result)

        instance = HandlerClass.__new__(HandlerClass)
        instance.path = "/callback?code=authcode&state=WRONG"
        instance.send_response = Mock()
        instance.send_header = Mock()
        instance.end_headers = Mock()
        instance.wfile = BytesIO()

        instance.do_GET()

        assert result.get("error") == "state_mismatch"
        assert "code" not in result
        assert event.is_set()

    def test_error_param_sets_error(self):
        result: dict = {}
        event = threading.Event()
        HandlerClass = make_callback_handler("state123", "/callback", event, result)

        instance = HandlerClass.__new__(HandlerClass)
        instance.path = "/callback?error=access_denied&state=state123"
        instance.send_response = Mock()
        instance.send_header = Mock()
        instance.end_headers = Mock()
        instance.wfile = BytesIO()

        instance.do_GET()

        assert result.get("error") == "access_denied"
        assert event.is_set()

    @pytest.mark.parametrize("path", [
        "/wrong-path?code=authcode&state=state123",
        "/?code=authcode&state=state123",
    ])
    def test_wrong_path_shows_waiting_message(self, path):
        """Handler should reject requests to wrong paths and show waiting message."""
        result: dict = {}
        event = threading.Event()
        HandlerClass = make_callback_handler("state123", "/callback", event, result)

        instance = HandlerClass.__new__(HandlerClass)
        instance.path = path
        instance.send_response = Mock()
        instance.send_header = Mock()
        instance.end_headers = Mock()
        instance.wfile = BytesIO()

        instance.do_GET()

        # Should NOT capture the code
        assert "code" not in result
        # Should NOT set the event
        assert not event.is_set()
        # Should return 200 OK with waiting message
        instance.send_response.assert_called_once_with(HTTPStatus.OK)




# ---------------------------------------------------------------------------
# Redirect URL Validation Tests
# ---------------------------------------------------------------------------

class TestRedirectUrlValidation:
    """Test redirect URL validation (hostname, port, scheme, path)."""

    @pytest.mark.parametrize("url", [
        "https://localhost:8080/callback",
        "https://127.0.0.1:8080/callback",
        "https://[::1]:8080/callback",
        "http://localhost:8080/callback",  # HTTP is now supported
        "http://127.0.0.1:8080/callback",
    ])
    def test_valid_redirect_urls(self, url):
        """Valid redirect URLs should pass validation."""
        _validate_redirect_url(urlparse(url))
        # No exception = success

    @pytest.mark.parametrize("url,error_pattern", [
        ("ftp://localhost:8080/callback", "Redirect URI scheme must be 'http' or 'https'"),
        ("https://example.com:8080/callback", "Redirect URI host must be localhost"),
        ("https://192.168.1.1:8080/callback", "Redirect URI host must be localhost"),
        ("https://localhost:80/callback", "port must be in range 1024-65535"),
        ("https://localhost:443/callback", "port must be in range 1024-65535"),
        ("https://localhost:1023/callback", "port must be in range 1024-65535"),
        ("https://localhost:70000/callback", "Port out of range 0-65535"), # Error thrown by urlparse
        ("https://localhost/callback", "missing port"),
        ("https://localhost:8080", "must include a path"),
        ("https://localhost:8080/", "path cannot be just '/'"),
        ("https://:8080/callback", "missing hostname"),
    ])
    def test_invalid_redirect_urls(self, url, error_pattern):
        """Invalid redirect URLs should raise ValueError with appropriate message."""
        with pytest.raises(ValueError, match=error_pattern):
            _validate_redirect_url(urlparse(url))


# ---------------------------------------------------------------------------
# start_callback_server — scheme-based SSL wrapping
# ---------------------------------------------------------------------------

class TestStartCallbackServer:
    """Verify the server socket is TLS-wrapped for https:// and plain for http://."""

    def test_https_scheme_produces_ssl_wrapped_socket(self):
        server = _start_server_on_free_port("https")
        try:
            assert isinstance(server.socket, ssl.SSLSocket)
        finally:
            server.server_close()

    def test_http_scheme_produces_plain_socket(self):
        server = _start_server_on_free_port("http")
        try:
            assert not isinstance(server.socket, ssl.SSLSocket)
        finally:
            server.server_close()
