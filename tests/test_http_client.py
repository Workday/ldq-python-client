# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for the shared OAuth HTTP client factory (http_client.py)."""

import json
import socket
import threading

import pytest

from workday_ldq import http_client
from workday_ldq.constants import (
    ConnectionRetry,
    RETRY_STATUS_CODES,
    DEFAULT_POOL_CONNECTIONS,
    DEFAULT_POOL_MAXSIZE,
    HTTP_METHOD_POST,
)


def _free_port() -> int:
    """Find an unused localhost port for a test-only server to bind to."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _make_scripted_handler(status_codes):
    """Build a request handler that returns `status_codes[i]` for the i-th POST
    request received (clamped to the last entry once the script runs out)."""
    from http.server import BaseHTTPRequestHandler

    class _Handler(BaseHTTPRequestHandler):
        request_count = 0

        def do_POST(self):
            _Handler.request_count += 1
            index = min(_Handler.request_count - 1, len(status_codes) - 1)
            status = status_codes[index]
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length:
                self.rfile.read(content_length)
            body = json.dumps({"access_token": "tok"}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass  # silence default request logging

    return _Handler


@pytest.fixture
def scripted_server():
    """Start a local HTTP server that replays a scripted sequence of POST status
    codes. Yields a function taking the status-code script and returning (url, handler_cls)."""
    from http.server import HTTPServer

    started = []

    def _start(status_codes):
        handler_cls = _make_scripted_handler(status_codes)
        port = _free_port()
        server = HTTPServer(("localhost", port), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started.append(server)
        return f"http://localhost:{port}/token", handler_cls

    yield _start

    for server in started:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Connection pooling
# ---------------------------------------------------------------------------

class TestConnectionPooling:

    def test_pool_sized_from_config(self):
        session = http_client.create_oauth_http_session()
        adapter = session.get_adapter("https://example.com")
        assert adapter._pool_connections == DEFAULT_POOL_CONNECTIONS
        assert adapter._pool_maxsize == DEFAULT_POOL_MAXSIZE

    def test_same_adapter_mounted_for_http_and_https(self):
        session = http_client.create_oauth_http_session()
        assert session.get_adapter("https://example.com") is session.get_adapter("http://example.com")


# ---------------------------------------------------------------------------
# Retry configuration wiring
# ---------------------------------------------------------------------------

class TestRetryConfiguration:

    def test_retries_only_post(self):
        session = http_client.create_oauth_http_session()
        adapter = session.get_adapter("https://example.com")
        assert set(adapter.max_retries.allowed_methods) == {HTTP_METHOD_POST}

    def test_retries_on_configured_status_codes(self):
        session = http_client.create_oauth_http_session()
        adapter = session.get_adapter("https://example.com")
        assert set(adapter.max_retries.status_forcelist) == set(RETRY_STATUS_CODES)

    def test_does_not_raise_when_status_retries_exhausted(self):
        session = http_client.create_oauth_http_session()
        adapter = session.get_adapter("https://example.com")
        assert adapter.max_retries.raise_on_status is False

    def test_uses_module_level_retry_config(self, monkeypatch):
        monkeypatch.setenv(ConnectionRetry.MAX_RETRIES.prop_name, "7")
        monkeypatch.setenv(ConnectionRetry.BACKOFF_MULTIPLIER.prop_name, "5.0")
        monkeypatch.setenv(ConnectionRetry.MAX_DELAY_SEC.prop_name, "42")
        monkeypatch.setenv(ConnectionRetry.BACKOFF_JITTER.prop_name, "false")

        session = http_client.create_oauth_http_session()
        retry = session.get_adapter("https://example.com").max_retries

        assert retry.total == 7
        assert retry.backoff_factor == 5.0
        assert retry._max_backoff == 42
        assert retry._use_jitter is False


class TestConnectionRetryEnvOverrides:
    """ConnectionRetry.resolve() reads os.environ live (not cached), independent
    of when http_client.py itself was imported."""

    def test_max_retries_env_override(self, monkeypatch):
        monkeypatch.setenv(ConnectionRetry.MAX_RETRIES.prop_name, "9")
        assert ConnectionRetry.MAX_RETRIES.resolve() == "9"

    def test_max_delay_env_override(self, monkeypatch):
        monkeypatch.setenv(ConnectionRetry.MAX_DELAY_SEC.prop_name, "17")
        assert ConnectionRetry.MAX_DELAY_SEC.resolve() == "17"

    def test_backoff_jitter_env_override(self, monkeypatch):
        monkeypatch.setenv(ConnectionRetry.BACKOFF_JITTER.prop_name, "false")
        assert ConnectionRetry.BACKOFF_JITTER.resolve().lower() == "false"

    def test_default_used_when_env_unset(self, monkeypatch):
        monkeypatch.delenv(ConnectionRetry.MAX_RETRIES.prop_name, raising=False)
        assert ConnectionRetry.MAX_RETRIES.resolve() == str(ConnectionRetry.MAX_RETRIES.default)


# ---------------------------------------------------------------------------
# _RetryWithJitter: backoff math
# ---------------------------------------------------------------------------

class TestRetryWithJitterBackoff:

    def _retry(self, **overrides):
        kwargs = dict(
            total=5,
            backoff_factor=2.0,
            status_forcelist=RETRY_STATUS_CODES,
            allowed_methods=[HTTP_METHOD_POST],
            raise_on_status=False,
            max_backoff=100,
            use_jitter=False,
        )
        kwargs.update(overrides)
        return http_client._RetryWithJitter(**kwargs)

    @staticmethod
    def _increment_n_times(retry, n):
        for i in range(n):
            retry = retry.increment(method=HTTP_METHOD_POST, response=None, error=Exception(f"err{i}"))
        return retry

    def test_no_backoff_before_second_error(self):
        retry = self._increment_n_times(self._retry(), 1)
        assert retry.get_backoff_time() == 0

    def test_exponential_backoff_without_jitter(self):
        retry = self._increment_n_times(self._retry(backoff_factor=2.0, max_backoff=100), 2)
        assert retry.get_backoff_time() == 4.0  # 2.0 * 2**(2-1)

    def test_backoff_capped_at_max_backoff(self):
        # Uncapped delay after 4 errors would be 2.0 * 2**3 = 16.0.
        retry = self._increment_n_times(self._retry(backoff_factor=2.0, max_backoff=3), 4)
        assert retry.get_backoff_time() == 3

    def test_jitter_scales_down_backoff(self, monkeypatch):
        monkeypatch.setattr(http_client.random, "random", lambda: 0.5)
        retry = self._increment_n_times(
            self._retry(backoff_factor=2.0, max_backoff=100, use_jitter=True), 2
        )
        assert retry.get_backoff_time() == 2.0  # 4.0 * 0.5

    def test_custom_kwargs_survive_increment(self):
        """Regression test: urllib3's Retry.new()/increment() rebuild via
        type(self)(**params) using only base Retry fields, so max_backoff/use_jitter
        must be forwarded explicitly or they silently revert to class defaults."""
        retry = self._retry(max_backoff=3, use_jitter=False)
        incremented = retry.increment(method=HTTP_METHOD_POST, response=None, error=Exception("boom"))
        assert incremented._max_backoff == 3
        assert incremented._use_jitter is False


# ---------------------------------------------------------------------------
# End-to-end retry behavior against a real HTTP server
# ---------------------------------------------------------------------------

class TestRetryEndToEnd:

    def test_retries_transient_5xx_then_succeeds(self, scripted_server, monkeypatch):
        monkeypatch.setenv(ConnectionRetry.MAX_RETRIES.prop_name, "1")
        url, handler_cls = scripted_server([503, 200])

        session = http_client.create_oauth_http_session()
        response = session.post(url, data={"grant_type": "client_credentials"}, timeout=5)

        assert response.status_code == 200
        assert handler_cls.request_count == 2

    def test_returns_final_response_when_retries_exhausted(self, scripted_server, monkeypatch):
        monkeypatch.setenv(ConnectionRetry.MAX_RETRIES.prop_name, "1")
        url, handler_cls = scripted_server([503])  # always fails

        session = http_client.create_oauth_http_session()
        response = session.post(url, data={"grant_type": "client_credentials"}, timeout=5)

        assert response.status_code == 503
        assert handler_cls.request_count == 2  # initial attempt + 1 retry, no exception raised

    def test_does_not_retry_on_success(self, scripted_server, monkeypatch):
        monkeypatch.setenv(ConnectionRetry.MAX_RETRIES.prop_name, "3")
        url, handler_cls = scripted_server([200])

        session = http_client.create_oauth_http_session()
        response = session.post(url, data={"grant_type": "client_credentials"}, timeout=5)

        assert response.status_code == 200
        assert handler_cls.request_count == 1
