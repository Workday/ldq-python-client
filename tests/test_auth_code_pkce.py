# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for OAuth 2.0 Authorization Code + PKCE authentication (RFC 7636)"""

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import requests

from workday_ldq.auth_code_pkce_grant import (
    AuthCodeGrantPKCEAuth,
    _generate_pkce_pair,
)
from workday_ldq.auth_model import AUTHORIZATION_CODE_PKCE
from workday_ldq.base_auth import CachedToken
from workday_ldq.config import LDQConfig
from workday_ldq.connector import create_connection
from workday_ldq.constants import (
    GrantType,
    TokenRequestParam,
    TokenParam,
    AuthzParam,
    JWTHeader,
    JWTAlgorithm,
    JWTClaim,
    JWTType,
    PKCE_CODE_VERIFIER_BYTE_LENGTH,
    PKCE_CODE_CHALLENGE_METHOD,
)
from workday_ldq.driver_property import DriverProperty


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(tenant: str = "test_tenant") -> str:
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
        DriverProperty.AUTH_MODEL:                      AUTHORIZATION_CODE_PKCE.name,
        DriverProperty.TOKEN_ENDPOINT:                  "https://example.myworkday.com/oauth/token",
        DriverProperty.AUTHORIZATION_ENDPOINT:          "https://example.myworkday.com/oauth/authorize",
        DriverProperty.REDIRECT_URL:                    "https://localhost:8888/callback",
        DriverProperty.CLIENT_ID:                       "my-client-id",
        DriverProperty.HOST:                            "example.myworkday.com",
    }
    props.update(overrides)
    return props


_BASE64URL_RE = re.compile(r'^[A-Za-z0-9\-_]+$')


# ---------------------------------------------------------------------------
# PKCE pair generation — JDBC parity
# ---------------------------------------------------------------------------

class TestPKCEPairGeneration:
    def test_verifier_length_is_86_chars(self):
        verifier, _ = _generate_pkce_pair()
        assert len(verifier) == 86

    def test_challenge_length_is_43_chars(self):
        _, challenge = _generate_pkce_pair()
        assert len(challenge) == 43

    def test_verifier_is_base64url_no_padding(self):
        verifier, _ = _generate_pkce_pair()
        assert _BASE64URL_RE.match(verifier), "verifier must be base64url"
        assert "=" not in verifier, "verifier must have no padding"

    def test_challenge_is_base64url_no_padding(self):
        _, challenge = _generate_pkce_pair()
        assert _BASE64URL_RE.match(challenge), "challenge must be base64url"
        assert "=" not in challenge, "challenge must have no padding"

    def test_challenge_equals_s256_of_verifier(self):
        """base64url(SHA-256(verifier_ascii)) == challenge — exact JDBC formula."""
        verifier, challenge = _generate_pkce_pair()
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert challenge == expected

    def test_verifier_byte_length_constant_matches_jdbc(self):
        """64 bytes is the JDBC CODE_VERIFIER_BYTE_LENGTH."""
        assert PKCE_CODE_VERIFIER_BYTE_LENGTH == 64

    def test_challenge_method_constant_is_s256(self):
        assert PKCE_CODE_CHALLENGE_METHOD == "S256"

    def test_fresh_pair_generated_each_call(self):
        v1, c1 = _generate_pkce_pair()
        v2, c2 = _generate_pkce_pair()
        assert v1 != v2
        assert c1 != c2


# ---------------------------------------------------------------------------
# LDQConfig — PKCE validation
# ---------------------------------------------------------------------------

class TestLDQConfigPKCE:
    def test_valid_config_requires_no_client_secret(self):
        cfg = LDQConfig(_base_props())
        assert cfg.client_id == "my-client-id"
        assert cfg.authorization_endpoint == "https://example.myworkday.com/oauth/authorize"
        assert cfg.redirect_url == "https://localhost:8888/callback"
        assert cfg.token_endpoint == "https://example.myworkday.com/oauth/token"

    def test_client_secret_not_required(self):
        props = _base_props()
        assert DriverProperty.CLIENT_SECRET not in props
        LDQConfig(props)  # must not raise

    def test_client_secret_accepted_if_provided_but_ignored(self):
        props = _base_props(**{DriverProperty.CLIENT_SECRET: "optional-secret"})
        LDQConfig(props)  # must not raise

    def test_missing_client_id_raises(self):
        props = _base_props()
        del props[DriverProperty.CLIENT_ID]
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

    def test_missing_token_endpoint_raises(self):
        props = _base_props()
        del props[DriverProperty.TOKEN_ENDPOINT]
        with pytest.raises(ValueError, match="Missing required properties"):
            LDQConfig(props)

    def test_http_token_endpoint_raises(self):
        props = _base_props(**{DriverProperty.TOKEN_ENDPOINT: "http://insecure.example.com/token"})
        with pytest.raises(ValueError, match="must use HTTPS"):
            LDQConfig(props)

    def test_http_authorization_endpoint_raises(self):
        props = _base_props(**{DriverProperty.AUTHORIZATION_ENDPOINT: "http://insecure.example.com/authorize"})
        with pytest.raises(ValueError, match="must use HTTPS"):
            LDQConfig(props)

    def test_from_file(self, tmp_path):
        props_file = tmp_path / "test.properties"
        props_file.write_text(
            "wd.authn.authModel=AUTHORIZATION_CODE_PKCE\n"
            "wd.authn.accessTokenEndpoint=https://example.myworkday.com/oauth/token\n"
            "wd.authn.authorizationEndpoint=https://example.myworkday.com/oauth/authorize\n"
            "wd.authn.redirectUrl=https://localhost:8888/callback\n"
            "wd.authn.clientId=my-client-id\n"
        )
        cfg = LDQConfig.from_file(str(props_file))
        assert cfg.client_id == "my-client-id"

    def test_create_authentication_returns_pkce_auth(self):
        cfg = LDQConfig(_base_props())
        auth = cfg.create_authentication()
        assert isinstance(auth, AuthCodeGrantPKCEAuth)


# ---------------------------------------------------------------------------
# _build_authorization_url — PKCE params in URL
# ---------------------------------------------------------------------------

class TestBuildAuthorizationUrl:
    def _auth(self) -> AuthCodeGrantPKCEAuth:
        auth = AuthCodeGrantPKCEAuth(LDQConfig(_base_props()))
        auth._code_verifier, auth._code_challenge = _generate_pkce_pair()
        return auth

    def test_url_contains_code_challenge(self):
        auth = self._auth()
        url = auth._build_authorization_url("test-state")
        assert "code_challenge=" in url

    def test_url_contains_s256_method(self):
        auth = self._auth()
        url = auth._build_authorization_url("test-state")
        assert "code_challenge_method=S256" in url

    def test_url_contains_base_params(self):
        auth = self._auth()
        url = auth._build_authorization_url("test-state")
        assert "response_type=code" in url
        assert "client_id=my-client-id" in url
        assert "state=test-state" in url
        assert "redirect_uri=" in url

    def test_challenge_in_url_matches_generated_challenge(self):
        auth = self._auth()
        url = auth._build_authorization_url("test-state")
        qs = parse_qs(urlparse(url).query)
        assert qs[AuthzParam.CODE_CHALLENGE][0] == auth._code_challenge
        assert qs[AuthzParam.CODE_CHALLENGE_METHOD][0] == "S256"

    def test_no_plain_method(self):
        auth = self._auth()
        url = auth._build_authorization_url("test-state")
        assert f"{AuthzParam.CODE_CHALLENGE_METHOD}=plain" not in url.lower()

    def test_raises_when_code_challenge_is_none(self):
        """Test that calling _build_authorization_url without PKCE pair raises RuntimeError"""
        auth = AuthCodeGrantPKCEAuth(LDQConfig(_base_props()))
        # Don't set _code_verifier or _code_challenge - they should be None

        with pytest.raises(RuntimeError, match="PKCE code_challenge is None"):
            auth._build_authorization_url("test-state")


# ---------------------------------------------------------------------------
# _exchange_code_for_token — sends code_verifier, NO client_secret
# ---------------------------------------------------------------------------

class TestExchangeCodeForToken:
    def _auth(self) -> AuthCodeGrantPKCEAuth:
        auth = AuthCodeGrantPKCEAuth(LDQConfig(_base_props()))
        auth._code_verifier, auth._code_challenge = _generate_pkce_pair()
        return auth

    def test_sends_code_verifier(self):
        access_token = _make_jwt()
        auth = self._auth()
        mock_post = Mock(return_value=Mock(
            status_code=200,
            json=lambda: {TokenParam.ACCESS_TOKEN: access_token, TokenParam.EXPIRES_IN: 3600},
            raise_for_status=Mock(),
        ))
        auth._http_session.post = mock_post
        auth._exchange_code_for_token("auth-code-xyz")

        body = mock_post.call_args[1]["data"]
        assert body[TokenRequestParam.CODE_VERIFIER] == auth._code_verifier

    def test_does_not_send_client_secret(self):
        access_token = _make_jwt()
        auth = self._auth()
        mock_post = Mock(return_value=Mock(
            status_code=200,
            json=lambda: {TokenParam.ACCESS_TOKEN: access_token, TokenParam.EXPIRES_IN: 3600},
            raise_for_status=Mock(),
        ))
        auth._http_session.post = mock_post
        auth._exchange_code_for_token("auth-code-xyz")

        body = mock_post.call_args[1]["data"]
        assert TokenRequestParam.CLIENT_SECRET not in body

    def test_sends_required_params(self):
        access_token = _make_jwt()
        auth = self._auth()
        mock_post = Mock(return_value=Mock(
            status_code=200,
            json=lambda: {TokenParam.ACCESS_TOKEN: access_token, TokenParam.EXPIRES_IN: 3600},
            raise_for_status=Mock(),
        ))
        auth._http_session.post = mock_post
        auth._exchange_code_for_token("auth-code-xyz")

        call_url = mock_post.call_args[0][0]
        body = mock_post.call_args[1]["data"]
        assert call_url == "https://example.myworkday.com/oauth/token"
        assert body[TokenRequestParam.GRANT_TYPE] == GrantType.AUTHORIZATION_CODE
        assert body[TokenRequestParam.CODE] == "auth-code-xyz"
        assert body[TokenRequestParam.CLIENT_ID] == "my-client-id"
        assert body[TokenRequestParam.REDIRECT_URI] == "https://localhost:8888/callback"

    def test_caches_refresh_token_when_returned(self):
        access_token = _make_jwt()
        auth = self._auth()
        mock_post = Mock(return_value=Mock(
            status_code=200,
            json=lambda: {TokenParam.ACCESS_TOKEN: access_token, TokenParam.EXPIRES_IN: 3600, TokenParam.REFRESH_TOKEN: "rt-xyz"},
            raise_for_status=Mock(),
        ))
        auth._http_session.post = mock_post
        auth._exchange_code_for_token("auth-code-xyz")
        assert auth._cached_token_data.refresh_token == "rt-xyz"

    def test_raises_when_code_verifier_is_none(self):
        """Test that calling _exchange_code_for_token without PKCE pair raises RuntimeError"""
        auth = AuthCodeGrantPKCEAuth(LDQConfig(_base_props()))
        # Don't set _code_verifier or _code_challenge - they should be None

        with pytest.raises(RuntimeError, match="PKCE code_verifier is None"):
            auth._exchange_code_for_token("test-code")


# ---------------------------------------------------------------------------
# try_refresh_token_grant — no client_secret for public clients
# ---------------------------------------------------------------------------

class TestRefreshTokenGrant:
    def _auth(self) -> AuthCodeGrantPKCEAuth:
        return AuthCodeGrantPKCEAuth(LDQConfig(_base_props()))

    def test_sends_refresh_without_client_secret(self):
        auth = self._auth()
        auth._cached_token_data = auth._cached_token_data._replace(refresh_token="refresh-token-abc")
        new_token = _make_jwt()
        mock_post = Mock(return_value=Mock(
            status_code=200,
            json=lambda: {TokenParam.ACCESS_TOKEN: new_token, TokenParam.EXPIRES_IN: 3600},
            raise_for_status=Mock(),
        ))
        auth._http_session.post = mock_post

        refreshed = auth.try_refresh_token_grant()

        body = mock_post.call_args[1]["data"]
        assert refreshed == new_token
        assert body[TokenRequestParam.GRANT_TYPE] == GrantType.REFRESH_TOKEN
        assert body[TokenRequestParam.REFRESH_TOKEN] == "refresh-token-abc"
        assert body[TokenRequestParam.CLIENT_ID] == "my-client-id"
        assert TokenRequestParam.CLIENT_SECRET not in body

    def test_returns_none_when_no_refresh_token(self):
        auth = self._auth()
        assert auth.try_refresh_token_grant() is None

    def test_clears_refresh_token_on_400(self):
        auth = self._auth()
        auth._cached_token_data = auth._cached_token_data._replace(refresh_token="expired-refresh-token")
        mock_response = Mock()
        mock_response.status_code = HTTPStatus.BAD_REQUEST
        http_error = requests.HTTPError("400 Bad Request")
        http_error.response = mock_response
        mock_response.raise_for_status.side_effect = http_error
        auth._http_session.post = Mock(return_value=mock_response)

        result = auth.try_refresh_token_grant()

        assert result is None
        assert auth._cached_token_data.refresh_token is None


# ---------------------------------------------------------------------------
# get_new_access_token — fresh PKCE pair per flow
# ---------------------------------------------------------------------------

class TestGetNewAccessToken:
    def test_fresh_pkce_pair_generated_each_full_flow(self):
        """Each call to get_new_access_token must produce a new verifier/challenge."""
        access_token = _make_jwt()
        auth = AuthCodeGrantPKCEAuth(LDQConfig(_base_props()))

        mock_server = Mock()
        mock_server.socket = Mock()
        mock_ssl_ctx = Mock()
        mock_ssl_ctx.wrap_socket.return_value = mock_server.socket

        verifiers = []

        def capture_exchange(code):
            verifiers.append(auth._code_verifier)
            auth._cached_token_data = CachedToken(access_token=access_token, expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
            return access_token

        def fake_make_handler(state, path, result_event, result):
            result["code"] = "sim-auth-code"
            result_event.set()
            return Mock()

        with patch("workday_ldq.callback_server.get_ssl_context", return_value=mock_ssl_ctx), \
             patch("workday_ldq.callback_server.HTTPServer", return_value=mock_server), \
             patch("workday_ldq.auth_code_grant.webbrowser.open"), \
             patch("workday_ldq.auth_code_grant.threading.Thread"), \
             patch("workday_ldq.callback_server.make_callback_handler", side_effect=fake_make_handler), \
             patch.object(auth, "_exchange_code_for_token", side_effect=capture_exchange):

            auth.get_new_access_token()
            # Expire token to force a second full flow
            auth._cached_token_data = CachedToken()
            auth.get_new_access_token()

        assert len(verifiers) == 2
        assert verifiers[0] != verifiers[1], "verifier must differ across flows"

    def test_authorization_url_includes_pkce_params(self):
        """The URL opened in the browser must contain code_challenge and S256."""
        access_token = _make_jwt()
        auth = AuthCodeGrantPKCEAuth(LDQConfig(_base_props()))

        mock_server = Mock()
        mock_server.socket = Mock()
        mock_ssl_ctx = Mock()
        mock_ssl_ctx.wrap_socket.return_value = mock_server.socket
        opened_urls = []

        def fake_make_handler(state, path, result_event, result):
            result["code"] = "sim-auth-code"
            result_event.set()
            return Mock()

        with patch("workday_ldq.callback_server.get_ssl_context", return_value=mock_ssl_ctx), \
             patch("workday_ldq.callback_server.HTTPServer", return_value=mock_server), \
             patch("workday_ldq.auth_code_grant.webbrowser.open", side_effect=opened_urls.append), \
             patch("workday_ldq.auth_code_grant.threading.Thread"), \
             patch("workday_ldq.callback_server.make_callback_handler", side_effect=fake_make_handler), \
             patch.object(auth, "_exchange_code_for_token", return_value=access_token):

            auth.get_new_access_token()

        assert len(opened_urls) == 1
        url = opened_urls[0]
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url


# ---------------------------------------------------------------------------
# create_connection — PKCE config path
# ---------------------------------------------------------------------------

class TestCreateConnectionPKCE:
    def test_pkce_config_creates_pkce_auth(self):
        cfg = LDQConfig(_base_props(**{
            DriverProperty.HOST: "acme.myworkday.com",
            DriverProperty.PORT: "443",
        }))
        with patch("workday_ldq.connector.trino") as mock_trino:
            create_connection(cfg)
            mock_trino.dbapi.connect.assert_called_once()
            call_kwargs = mock_trino.dbapi.connect.call_args[1]
            assert isinstance(call_kwargs["auth"], AuthCodeGrantPKCEAuth)
            assert call_kwargs["host"] == "acme.myworkday.com"
            assert call_kwargs["http_scheme"] == "https"
