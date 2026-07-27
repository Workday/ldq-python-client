# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""OAuth 2.0 Authorization Code Grant authentication for Workday Live Data Query (LDQ) (RFC 6749 §4.1)"""

import logging
import secrets
import threading
import webbrowser
from http import HTTPStatus
from typing import Dict, Optional
from urllib.parse import urlencode

import requests

from .base_auth import BaseAuth, CachedToken
from .callback_server import start_callback_server
from .constants import (
    GrantType,
    TokenRequestParam,
    TokenParam,
    AuthzParam,
    AuthzResponseType,
    OAUTH_TOKEN_ENDPOINT_HEADERS,
    DEFAULT_CALLBACK_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


class AuthCodeGrantAuth(BaseAuth):
    """
    Trino Authentication using OAuth 2.0 Authorization Code Grant (RFC 6749 §4.1).

    Flow:
      1.  Generate cryptographically random state (CSRF protection)
      2.  Build authorization URL and open user's system browser
      3.  Start local callback server with self-signed certificate
      4.  Wait up to 3 minutes for the browser to GET back the auth code
      5.  Validate state parameter (CSRF check)
      6.  Exchange authorization code for an access token
      7.  Cache token; refresh on expiry or 401
      8.  Inject Bearer + X-Tenant + HEADER_EXTRA_CREDENTIAL headers, see BaseAuth
    """

    CALLBACK_TIMEOUT_SECONDS = DEFAULT_CALLBACK_TIMEOUT_SECONDS  # 3 minutes

    def get_new_access_token(self) -> str:
        """Run the full Authorization Code Grant flow and return a fresh access token."""
        state = secrets.token_urlsafe(16)
        auth_url = self._build_authorization_url(state)

        result: Dict[str, str] = {}
        result_event = threading.Event()

        server = start_callback_server(self.config.redirect_url, state, result_event, result)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            webbrowser.open(auth_url)
            if not result_event.wait(timeout=self.CALLBACK_TIMEOUT_SECONDS):
                raise TimeoutError(
                    f"No authorization code received within {self.CALLBACK_TIMEOUT_SECONDS}s. "
                    "Check that the browser completed the login and was redirected to the callback URL."
                )
            if TokenParam.ERROR in result:
                detail = result.get(TokenParam.ERROR_DESCRIPTION)
                msg = result[TokenParam.ERROR]
                raise ValueError(
                    f"Authorization Code Grant failed: {msg}"
                    + (f" — {detail}" if detail else "")
                )

            code = result[AuthzParam.CODE]
        finally:
            server.shutdown()
            server.server_close()

        return self._exchange_code_for_token(code)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_authorization_url(self, state: str) -> str:
        params = {
            AuthzParam.RESPONSE_TYPE: AuthzResponseType.CODE,
            AuthzParam.CLIENT_ID: self.config.client_id,
            AuthzParam.REDIRECT_URI: self.config.redirect_url,
            AuthzParam.STATE: state,
        }
        return f"{self.config.authorization_endpoint}?{urlencode(params)}"

    def _exchange_code_for_token(self, code: str) -> str:
        resp = self._http_session.post(
            self.config.token_endpoint,
            data={
                TokenRequestParam.GRANT_TYPE: GrantType.AUTHORIZATION_CODE,
                TokenRequestParam.CODE: code,
                TokenRequestParam.REDIRECT_URI: self.config.redirect_url,
                TokenRequestParam.CLIENT_ID: self.config.client_id,
                TokenRequestParam.CLIENT_SECRET: self.config.client_secret,
            },
            headers=OAUTH_TOKEN_ENDPOINT_HEADERS,
            timeout=self.HTTP_REQUEST_TIMEOUT_SECONDS,
        )
        return self._handle_token_response(resp)

    def try_refresh_token_grant(self) -> Optional[str]:
        """
        Try to refresh access token using OAuth 2.0 Refresh Token Grant (RFC 6749 §6).
        Returns new access token on success, None on failure.
        """
        if not self._cached_token_data.refresh_token:
            return None

        try:
            resp = self._http_session.post(
                self.config.token_endpoint,
                data={
                    TokenRequestParam.GRANT_TYPE: GrantType.REFRESH_TOKEN,
                    TokenRequestParam.REFRESH_TOKEN: self._cached_token_data.refresh_token,
                    TokenRequestParam.CLIENT_ID: self.config.client_id,
                    TokenRequestParam.CLIENT_SECRET: self.config.client_secret,
                },
                headers=OAUTH_TOKEN_ENDPOINT_HEADERS,
                timeout=self.HTTP_REQUEST_TIMEOUT_SECONDS,
            )
            return self._handle_token_response(resp)
        except requests.HTTPError as e:
            # If the server explicitly rejects the refresh, clear it (most commonly invalid_grant).
            # RFC 6749 §5.2: 400 (invalid_grant), 401 (Unauthorized), or 403 (Forbidden)
            # all indicate the refresh token is invalid and should be discarded.
            status_code = getattr(getattr(e, "response", None), "status_code", None)
            # Only the HTTP status code is logged here, never a token value.
            # nosemgrep: python-logger-credential-disclosure
            logger.debug(
                "Refresh-token grant rejected (http_status=%s); falling back to full auth flow",
                status_code,
            )
            if status_code in (HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                # Clear the refresh token by creating a new CachedToken without it
                self._cached_token_data = CachedToken()
            return None
        except Exception as e:
            # Network errors and unexpected failures: fall back without invalidating refresh token.
            # Only the HTTP status code is logged here, never a token value.
            # nosemgrep: python-logger-credential-disclosure
            logger.debug(
                "Refresh-token grant failed (%s); falling back to full auth flow",
                type(e).__name__,
            )
            return None


