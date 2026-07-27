# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for OAuth 2.0 Authorization Code Grant authentication"""

import base64
import json
import threading
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest.mock import Mock, patch

import pytest
import requests
from trino.constants import HEADER_EXTRA_CREDENTIAL

from workday_ldq.auth_code_grant import AuthCodeGrantAuth
from workday_ldq.auth_model import AUTHORIZATION_CODE
from workday_ldq.base_auth import CachedToken
from workday_ldq.constants import (
    HTTPHeader,
    GrantType,
    TokenRequestParam,
    TokenParam,
    JWTHeader,
    JWTAlgorithm,
    JWTClaim,
    JWTType,
)
from workday_ldq.config import LDQConfig
from workday_ldq.connector import create_connection
from workday_ldq.driver_property import DriverProperty


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(tenant: str = "test_tenant") -> str:
    """Build a fake JWT with a tenant claim (not cryptographically signed)."""
    header = base64.urlsafe_b64encode(
        json.dumps({JWTHeader.ALG: JWTAlgorithm.RS256, JWTHeader.TYP: JWTType.JWT}).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({JWTClaim.TENANT: tenant, JWTClaim.EXP: 9999999999}).encode()
    ).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"fake").decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


def _base_props(**overrides) -> dict:
    props = {
        DriverProperty.AUTH_MODEL:                      AUTHORIZATION_CODE.name,
        DriverProperty.TOKEN_ENDPOINT:                  "https://example.myworkday.com/oauth/token",
        DriverProperty.AUTHORIZATION_ENDPOINT:          "https://example.myworkday.com/oauth/authorize",
        DriverProperty.REDIRECT_URL:                    "https://localhost:8888/callback",
        DriverProperty.CLIENT_ID:                       "my-client-id",
        DriverProperty.CLIENT_SECRET:                   "my-client-secret",
        DriverProperty.HOST:                            "example.myworkday.com",
    }
    props.update(overrides)
    return props


# ---------------------------------------------------------------------------
# LDQConfig — validation
# ---------------------------------------------------------------------------

class TestLDQConfig:
    def test_valid_config(self):
        cfg = LDQConfig(_base_props())
        assert cfg.client_id == "my-client-id"
        assert cfg.client_secret == "my-client-secret"
        assert cfg.authorization_endpoint == "https://example.myworkday.com/oauth/authorize"
        assert cfg.redirect_url == "https://localhost:8888/callback"
        assert cfg.token_endpoint == "https://example.myworkday.com/oauth/token"

    def test_missing_client_secret_raises(self):
        props = _base_props()
        del props[DriverProperty.CLIENT_SECRET]
        with pytest.raises(ValueError, match="Missing required properties"):
            LDQConfig(props)

    def test_missing_authorization_endpoint_raises(self):
        props = _base_props()
        del props[DriverProperty.AUTHORIZATION_ENDPOINT]
        with pytest.raises(ValueError, match="Missing required properties"):
            LDQConfig(props)

    def test_missing_redirect_url_raises(self):
        props = _base_props()
        del props[DriverProperty.REDIRECT_URL]
        with pytest.raises(ValueError, match="Missing required properties"):
            LDQConfig(props)

    def test_http_token_endpoint_raises(self):
        props = _base_props(**{DriverProperty.TOKEN_ENDPOINT: "http://insecure.example.com/token"})
        with pytest.raises(ValueError, match="must use HTTPS"):
            LDQConfig(props)

    def test_from_file(self, tmp_path):
        props_file = tmp_path / "test.properties"
        props_file.write_text(
            "wd.authn.authModel=AUTHORIZATION_CODE\n"
            "wd.authn.accessTokenEndpoint=https://example.myworkday.com/oauth/token\n"
            "wd.authn.authorizationEndpoint=https://example.myworkday.com/oauth/authorize\n"
            "wd.authn.redirectUrl=https://localhost:8888/callback\n"
            "wd.authn.clientId=my-client-id\n"
            "wd.authn.clientSecret=my-client-secret\n"
        )
        cfg = LDQConfig.from_file(str(props_file))
        assert cfg.client_id == "my-client-id"

    def test_default_host_port(self):
        cfg = LDQConfig(_base_props())
        assert cfg.host == "example.myworkday.com"
        assert cfg.port == 443
        assert cfg.catalog == "workday_core"
        assert cfg.schema == "public"

    def test_http_timeout_default_value(self):
        """Test that http_timeout returns default value of 30 when not specified"""
        cfg = LDQConfig(_base_props())
        assert cfg.http_timeout == 30

    def test_http_timeout_custom_value(self):
        """Test that http_timeout can be configured via wd.http.timeout property"""
        props = _base_props()
        props[DriverProperty.HTTP_REQUEST_TIMEOUT] = "120"
        cfg = LDQConfig(props)
        assert cfg.http_timeout == 120

    def test_http_timeout_string_converted_to_int(self):
        """Test that http_timeout property value is converted from string to float"""
        props = _base_props()
        props[DriverProperty.HTTP_REQUEST_TIMEOUT] = "60"
        cfg = LDQConfig(props)
        assert cfg.http_timeout == 60
        assert isinstance(cfg.http_timeout, float)

    def test_session_properties_not_specified(self):
        """Test that session_properties returns None when not specified"""
        cfg = LDQConfig(_base_props())
        assert cfg.session_properties is None

    def test_session_properties_single_property(self):
        """Test parsing a single session property"""
        props = _base_props()
        props[DriverProperty.SESSION_PROPERTIES] = "query_max_run_time=1h"
        cfg = LDQConfig(props)
        assert cfg.session_properties == {"query_max_run_time": "1h"}

    def test_session_properties_multiple_properties(self):
        """Test parsing multiple comma-separated session properties"""
        props = _base_props()
        props[DriverProperty.SESSION_PROPERTIES] = (
            "query_max_run_time=1h,join_distribution_type=broadcast,exchange_order=ANY"
        )
        cfg = LDQConfig(props)
        assert cfg.session_properties == {
            "query_max_run_time": "1h",
            "join_distribution_type": "broadcast",
            "exchange_order": "ANY",
        }

    def test_session_properties_no_equality_and_value(self):
        """Malformed property without '=' raises RuntimeError"""
        props = _base_props()
        props[DriverProperty.SESSION_PROPERTIES] = "query_max_run_time"
        cfg = LDQConfig(props)
        with pytest.raises(RuntimeError, match="Invalid session property format"):
            _ = cfg.session_properties

    def test_session_properties_no_value(self):
        """Empty value raises RuntimeError"""
        props = _base_props()
        props[DriverProperty.SESSION_PROPERTIES] = "query_max_run_time="
        cfg = LDQConfig(props)
        with pytest.raises(RuntimeError, match="value cannot be empty"):
            _ = cfg.session_properties

    def test_session_properties_with_whitespace(self):
        """Test that whitespace is properly trimmed from session properties"""
        props = _base_props()
        props[DriverProperty.SESSION_PROPERTIES] = (
            " query_max_run_time = 2h , join_distribution_type = local "
        )
        cfg = LDQConfig(props)
        assert cfg.session_properties == {
            "query_max_run_time": "2h",
            "join_distribution_type": "local",
        }


# ---------------------------------------------------------------------------
# AuthCodeGrantAuth — token management
# ---------------------------------------------------------------------------

class TestTokenManagement:
    @staticmethod
    def _auth() -> AuthCodeGrantAuth:
        return AuthCodeGrantAuth(LDQConfig(_base_props()))

    def test_token_initially_invalid(self):
        auth = self._auth()
        assert not auth._is_token_valid()

    def test_valid_token_not_refreshed(self):
        auth = self._auth()
        token = _make_jwt()
        auth._cached_token_data = CachedToken(access_token=token, expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        assert auth._is_token_valid()
        assert auth.get_token() == token

    def test_expired_token_is_invalid(self):
        auth = self._auth()
        auth._cached_token_data = CachedToken(access_token=_make_jwt(), expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
        assert not auth._is_token_valid()

    def test_token_near_expiry_is_invalid(self):
        """Token within 5 minutes of expiry must be treated as invalid."""
        auth = self._auth()
        # Token expires in 4 minutes - should be treated as invalid (buffer is 5 minutes)
        auth._cached_token_data = CachedToken(access_token=_make_jwt(), expires_at=datetime.now(timezone.utc) + timedelta(minutes=4))
        assert not auth._is_token_valid()

    @patch("workday_ldq.auth_code_grant.AuthCodeGrantAuth.get_new_access_token")
    def test_get_token_calls_refresh_when_expired(self, mock_refresh):
        mock_refresh.return_value = "brand-new-token"
        auth = self._auth()
        token = auth.get_token()
        assert token == "brand-new-token"
        mock_refresh.assert_called_once()


# ---------------------------------------------------------------------------
# AuthCodeGrantAuth — _exchange_code_for_token
# ---------------------------------------------------------------------------

class TestExchangeCodeForToken:
    @staticmethod
    def _auth() -> AuthCodeGrantAuth:
        return AuthCodeGrantAuth(LDQConfig(_base_props()))

    def test_exchange_success(self):
        access_token = _make_jwt()
        mock_response = Mock(
            status_code=200,
            json=lambda: {TokenParam.ACCESS_TOKEN: access_token, TokenParam.EXPIRES_IN: 3600},
        )
        mock_response.raise_for_status = Mock()

        auth = self._auth()
        mock_post = Mock(return_value=mock_response)
        auth._http_session.post = mock_post
        token = auth._exchange_code_for_token("auth-code-xyz")

        assert token == access_token
        assert auth._cached_token_data.access_token == access_token
        assert auth._cached_token_data.expires_at is not None

        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://example.myworkday.com/oauth/token"
        body = call_kwargs[1]["data"]
        assert body[TokenRequestParam.GRANT_TYPE] == GrantType.AUTHORIZATION_CODE
        assert body[TokenRequestParam.CODE] == "auth-code-xyz"
        assert body[TokenRequestParam.CLIENT_ID] == "my-client-id"
        assert body[TokenRequestParam.CLIENT_SECRET] == "my-client-secret"
        assert body[TokenRequestParam.REDIRECT_URI] == "https://localhost:8888/callback"

    def test_exchange_success_with_refresh_token(self):
        """Test that refresh token is cached when returned by token endpoint."""
        access_token = _make_jwt()
        refresh_token = "refresh-token-xyz"
        mock_response = Mock(
            status_code=200,
            json=lambda: {
                TokenParam.ACCESS_TOKEN: access_token,
                TokenParam.EXPIRES_IN: 3600,
                TokenParam.REFRESH_TOKEN: refresh_token,
            },
        )
        mock_response.raise_for_status = Mock()

        auth = self._auth()
        auth._http_session.post = Mock(return_value=mock_response)
        token = auth._exchange_code_for_token("auth-code-xyz")

        assert token == access_token
        assert auth._cached_token_data.access_token == access_token
        assert auth._cached_token_data.refresh_token == refresh_token
        assert auth._cached_token_data.expires_at is not None

    def test_exchange_http_error_raises(self):
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = Exception("401 Unauthorized")

        auth = self._auth()
        auth._http_session.post = Mock(return_value=mock_response)
        with pytest.raises(Exception, match="401 Unauthorized"):
            auth._exchange_code_for_token("bad-code")


# ---------------------------------------------------------------------------
# AuthCodeGrantAuth — Refresh Token Grant
# ---------------------------------------------------------------------------

class TestRefreshTokenGrant:
    @staticmethod
    def _auth() -> AuthCodeGrantAuth:
        return AuthCodeGrantAuth(LDQConfig(_base_props()))

    def test_refresh_token_grant_success(self):
        """Test successful refresh token grant returns new access token."""
        auth = self._auth()
        # Simulate having a cached refresh token from previous auth
        auth._cached_token_data = CachedToken(access_token=_make_jwt(), expires_at=datetime.now(timezone.utc) - timedelta(seconds=10), refresh_token="refresh-token-abc")

        new_access_token = _make_jwt()
        new_refresh_token = "refresh-token-xyz"
        mock_response = Mock(
            status_code=200,
            json=lambda: {
                TokenParam.ACCESS_TOKEN: new_access_token,
                TokenParam.EXPIRES_IN: 3600,
                TokenParam.REFRESH_TOKEN: new_refresh_token,
            },
        )
        mock_response.raise_for_status = Mock()
        mock_post = Mock(return_value=mock_response)
        auth._http_session.post = mock_post

        refreshed = auth.try_refresh_token_grant()

        assert refreshed == new_access_token
        assert auth._cached_token_data.access_token == new_access_token
        assert auth._cached_token_data.refresh_token == new_refresh_token

        # Verify the POST request
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://example.myworkday.com/oauth/token"
        body = call_kwargs[1]["data"]
        assert body[TokenRequestParam.GRANT_TYPE] == GrantType.REFRESH_TOKEN
        assert body[TokenRequestParam.REFRESH_TOKEN] == "refresh-token-abc"
        assert body[TokenRequestParam.CLIENT_ID] == "my-client-id"
        assert body[TokenRequestParam.CLIENT_SECRET] == "my-client-secret"

    def test_refresh_token_grant_keeps_old_refresh_token_if_not_rotated(self):
        """Test that old refresh token is kept if new one not provided."""
        auth = self._auth()
        auth._cached_token_data = auth._cached_token_data._replace(refresh_token="refresh-token-abc")

        new_access_token = _make_jwt()
        mock_response = Mock(
            status_code=200,
            json=lambda: {
                TokenParam.ACCESS_TOKEN: new_access_token,
                TokenParam.EXPIRES_IN: 3600,
                # No new refresh_token in response
            },
        )
        mock_response.raise_for_status = Mock()
        auth._http_session.post = Mock(return_value=mock_response)

        refreshed = auth.try_refresh_token_grant()

        assert refreshed == new_access_token
        assert auth._cached_token_data.refresh_token == "refresh-token-abc"  # No refresh token in response -> keep old

    def test_refresh_token_grant_failure_clears_refresh_token(self):
        """Test that failed refresh clears the refresh token."""
        auth = self._auth()
        auth._cached_token_data = auth._cached_token_data._replace(refresh_token="expired-refresh-token")

        mock_response = Mock()
        mock_response.status_code = HTTPStatus.BAD_REQUEST
        mock_response.text = f'{{"{TokenParam.ERROR}": "invalid_grant"}}'
        http_error = requests.HTTPError("400 Bad Request")
        http_error.response = mock_response
        mock_response.raise_for_status.side_effect = http_error
        auth._http_session.post = Mock(return_value=mock_response)

        refreshed = auth.try_refresh_token_grant()

        assert refreshed is None
        assert auth._cached_token_data.refresh_token is None  # Cleared on failure

    def test_refresh_token_grant_no_refresh_token_returns_none(self):
        """Test that refresh grant returns None when no refresh token cached."""
        auth = self._auth()
        assert auth._cached_token_data.refresh_token is None

        refreshed = auth.try_refresh_token_grant()

        assert refreshed is None

    @patch("workday_ldq.auth_code_grant.AuthCodeGrantAuth.get_new_access_token")
    def test_get_token_uses_refresh_token_before_full_auth(self, mock_full_auth):
        """Test that get_token tries refresh token before falling back to full auth."""
        auth = self._auth()
        auth._cached_token_data = CachedToken(access_token=_make_jwt(), expires_at=datetime.now(timezone.utc) - timedelta(seconds=10), refresh_token="refresh-token-abc")

        new_access_token = _make_jwt()
        mock_response = Mock(
            status_code=200,
            json=lambda: {
                TokenParam.ACCESS_TOKEN: new_access_token,
                TokenParam.EXPIRES_IN: 3600,
            },
        )
        mock_response.raise_for_status = Mock()
        auth._http_session.post = Mock(return_value=mock_response)

        token = auth.get_token()

        assert token == new_access_token
        # Full auth should NOT be called since refresh succeeded
        mock_full_auth.assert_not_called()

    def test_get_token_falls_back_to_full_auth_when_refresh_fails(self):
        """Test that get_token falls back to full auth when refresh token fails."""
        auth = self._auth()
        auth._cached_token_data = CachedToken(access_token=_make_jwt(), expires_at=datetime.now(timezone.utc) - timedelta(seconds=10), refresh_token="expired-refresh-token")

        full_auth_token = _make_jwt()

        # Simulate refresh failure and mock the full auth flow
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = Exception("400 Bad Request")
        auth._http_session.post = Mock(return_value=mock_response)

        with patch.object(auth, 'get_new_access_token', return_value=full_auth_token) as mock_full_auth:
            token = auth.get_token()

        assert token == full_auth_token
        mock_full_auth.assert_called_once()


# ---------------------------------------------------------------------------
# AuthCodeGrantAuth — _build_authorization_url
# ---------------------------------------------------------------------------

class TestBuildAuthorizationUrl:
    def test_url_contains_required_params(self):
        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))
        state = "test-state-123"
        url = auth._build_authorization_url(state)

        assert url.startswith("https://example.myworkday.com/oauth/authorize?")
        assert "response_type=code" in url
        assert "client_id=my-client-id" in url
        assert f"state={state}" in url
        assert "redirect_uri=" in url


# ---------------------------------------------------------------------------
# AuthCodeGrantAuth — _set_auth_headers
# ---------------------------------------------------------------------------

class TestSetAuthHeaders:
    def test_headers_injected(self):
        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))
        token = _make_jwt("acme_corp")

        session = Mock()
        session.headers = {}
        auth._set_auth_headers(session, token)

        assert session.headers[HTTPHeader.AUTHORIZATION] == f"Bearer {token}"
        assert session.headers[HTTPHeader.TENANT] == "acme_corp"
        assert session.headers[HEADER_EXTRA_CREDENTIAL] == f"token={token}"

    def test_missing_tenant_claim_raises(self):
        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))
        # JWT with no tenant claim
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"sub":"user"}').decode().rstrip("=")
        bad_token = f"{header}.{payload}.sig"

        session = Mock()
        session.headers = {}
        with pytest.raises(Exception, match="Tenant claim is missing"):
            auth._set_auth_headers(session, bad_token)


# ---------------------------------------------------------------------------
# AuthCodeGrantAuth — set_http_session (URL rewriting + 401 retry)
# ---------------------------------------------------------------------------

class TestSetHttpSession:
    @staticmethod
    def _session_with_token(token: str):
        """Return a mock session pre-configured as set_http_session would leave it."""
        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))
        auth._cached_token_data = CachedToken(access_token=token, expires_at=datetime.now(timezone.utc) + timedelta(hours=1))

        session = Mock()
        session.headers = {}

        # set_http_session replaces session.request with the interceptor
        auth.set_http_session(session)
        return session, auth


    def test_url_rewritten_with_host_and_prefix(self):
        token = _make_jwt()
        session, _ = self._session_with_token(token)

        captured = []

        def original_request(method, url, **kwargs):
            captured.append(url)
            return Mock(status_code=200)

        # Inject the original request so the interceptor can call it
        # set_http_session already replaced session.request, so we need to
        # rebuild: create fresh auth + session
        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))
        auth._cached_token_data = CachedToken(access_token=token, expires_at=datetime.now(timezone.utc) + timedelta(hours=1))

        session2 = Mock()
        session2.headers = {}
        session2.request = original_request
        auth.set_http_session(session2)

        session2.request("GET", "https://old-host:9090/v1/statement")

        assert len(captured) == 1
        assert "example.myworkday.com:443" in captured[0]
        assert "/dataservice/v1/statement" in captured[0]


    def test_401_triggers_token_refresh_and_retry(self):
        initial_token = _make_jwt("tenant_a")
        refreshed_token = _make_jwt("tenant_a")

        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))
        auth._cached_token_data = CachedToken(access_token=initial_token, expires_at=datetime.now(timezone.utc) + timedelta(hours=1))

        call_count = [0]
        responses = [Mock(status_code=HTTPStatus.UNAUTHORIZED, close=Mock()), Mock(status_code=HTTPStatus.OK)]

        def original_request(method, url, **kwargs):
            resp = responses[call_count[0]]
            call_count[0] += 1
            return resp

        session = Mock()
        session.headers = {}
        session.request = original_request

        with patch.object(auth, "get_new_access_token", return_value=refreshed_token):
            auth.set_http_session(session)
            final_response = session.request("GET", "https://host/v1/statement")

        assert call_count[0] == 2
        assert final_response.status_code == HTTPStatus.OK
        assert session.headers[HTTPHeader.AUTHORIZATION] == f"Bearer {refreshed_token}"
        assert session.headers[HTTPHeader.TENANT] == "tenant_a"
        assert responses[0].close.called


# ---------------------------------------------------------------------------
# get_new_access_token — browser interaction (mocked end-to-end)
# ---------------------------------------------------------------------------

class TestGetNewAccessToken:
    def test_get_new_access_token_calls_exchange_after_callback(self):
        """get_new_access_token should open the browser, then call _exchange_code_for_token with the code."""
        access_token = _make_jwt()
        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))

        mock_server = Mock()
        mock_server.socket = Mock()
        mock_ssl_ctx = Mock()
        mock_ssl_ctx.wrap_socket.return_value = mock_server.socket

        # Fake handler factory: immediately delivers a code into the shared result dict
        # and fires the event, simulating a browser callback without a real HTTP server.
        def fake_make_handler(state, path, result_event, result):
            result["code"] = "sim-auth-code-abc"
            result_event.set()
            return Mock()

        with patch("workday_ldq.callback_server.get_ssl_context", return_value=mock_ssl_ctx), \
             patch("workday_ldq.callback_server.HTTPServer", return_value=mock_server), \
             patch("workday_ldq.auth_code_grant.webbrowser.open"), \
             patch("workday_ldq.auth_code_grant.threading.Thread"), \
             patch("workday_ldq.callback_server.make_callback_handler", side_effect=fake_make_handler), \
             patch.object(auth, "_exchange_code_for_token", return_value=access_token) as mock_exchange:

            token = auth.get_new_access_token()

        assert token == access_token
        mock_exchange.assert_called_once_with("sim-auth-code-abc")
        mock_server.shutdown.assert_called_once()

    def test_missing_port_in_redirect_url_raises(self):
        """Validation now happens during config initialization, not during token refresh."""
        props = _base_props(**{DriverProperty.REDIRECT_URL: "https://localhost/callback"})
        with pytest.raises(ValueError, match="missing port"):
            LDQConfig(props)

    @patch("workday_ldq.auth_code_grant.AuthCodeGrantAuth._exchange_code_for_token")
    @patch("workday_ldq.auth_code_grant.webbrowser.open")
    @patch("workday_ldq.callback_server.HTTPServer")
    @patch("workday_ldq.callback_server.get_ssl_context")
    def test_timeout_raises(self, mock_ssl, mock_server_cls, mock_browser, mock_exchange):
        """If no callback arrives, TimeoutError is raised."""
        mock_ssl.return_value = Mock(wrap_socket=Mock(return_value=Mock()))
        mock_server_instance = Mock()
        mock_server_instance.socket = Mock()
        mock_server_cls.return_value = mock_server_instance

        auth = AuthCodeGrantAuth(LDQConfig(_base_props()))
        auth.CALLBACK_TIMEOUT_SECONDS = 0  # immediate timeout

        with pytest.raises(TimeoutError, match="No authorization code received"):
            auth.get_new_access_token()

        mock_server_instance.shutdown.assert_called_once()


# ---------------------------------------------------------------------------
# create_connection — LDQConfig path
# ---------------------------------------------------------------------------

class TestCreateConnection:
    def test_auth_code_config_passes_correct_params(self):
        cfg = LDQConfig(_base_props(**{
            DriverProperty.HOST: "acme.myworkday.com",
            DriverProperty.PORT: "443",
            DriverProperty.CATALOG: "workday_core",
            DriverProperty.SCHEMA: "public",
        }))

        with patch("workday_ldq.connector.trino") as mock_trino:
            create_connection(cfg)
            mock_trino.dbapi.connect.assert_called_once()
            call_kwargs = mock_trino.dbapi.connect.call_args[1]
            assert call_kwargs["host"] == "acme.myworkday.com"
            assert call_kwargs["http_scheme"] == "https"
            assert isinstance(call_kwargs["auth"], AuthCodeGrantAuth)
