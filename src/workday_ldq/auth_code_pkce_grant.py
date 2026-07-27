# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""OAuth 2.0 Authorization Code Grant with PKCE authentication for Workday Live Data Query (LDQ) (RFC 7636)"""

import base64
import hashlib
import logging
import os
from http import HTTPStatus
from typing import Optional
from urllib.parse import urlencode

import requests

from .auth_code_grant import AuthCodeGrantAuth
from .base_auth import CachedToken
from .constants import (
    GrantType,
    TokenRequestParam,
    AuthzParam,
    OAUTH_TOKEN_ENDPOINT_HEADERS,
    PKCE_CODE_VERIFIER_BYTE_LENGTH,
    PKCE_CODE_CHALLENGE_METHOD,
)

logger = logging.getLogger(__name__)


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a fresh (code_verifier, code_challenge) pair per RFC 7636."""
    verifier_bytes = os.urandom(PKCE_CODE_VERIFIER_BYTE_LENGTH)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class AuthCodeGrantPKCEAuth(AuthCodeGrantAuth):
    """
    Trino Authentication using OAuth 2.0 Authorization Code + PKCE (RFC 7636).

    Identical to AuthCodeGrantAuth but replaces client_secret with a
    code_verifier/code_challenge pair, allowing use with public clients
    (no shared secret required).

    code_verifier  — 64 random bytes → base64url, no padding → 86 chars
    code_challenge — SHA-256(verifier) → base64url, no padding → 43 chars

    """

    def __init__(self, config) -> None:
        super().__init__(config)
        self._code_verifier: Optional[str] = None
        self._code_challenge: Optional[str] = None

    def get_new_access_token(self) -> str:
        """Generate a fresh PKCE pair before the full Authorization Code flow."""
        self._code_verifier, self._code_challenge = _generate_pkce_pair()
        return super().get_new_access_token()

    def _build_authorization_url(self, state: str) -> str:
        base_url = super()._build_authorization_url(state)

        if self._code_challenge is None:
            raise RuntimeError(
                "PKCE code_challenge is None. "
                "Call get_new_access_token() to generate a fresh PKCE pair."
            )

        pkce_params = urlencode({
            AuthzParam.CODE_CHALLENGE: self._code_challenge,
            AuthzParam.CODE_CHALLENGE_METHOD: PKCE_CODE_CHALLENGE_METHOD,
        })
        return f"{base_url}&{pkce_params}"

    def _exchange_code_for_token(self, code: str) -> str:
        if self._code_verifier is None:
            raise RuntimeError(
                "PKCE code_verifier is None. "
                "Call get_new_access_token() to generate a fresh PKCE pair."
            )

        resp = self._http_session.post(
            self.config.token_endpoint,
            data={
                TokenRequestParam.GRANT_TYPE: GrantType.AUTHORIZATION_CODE,
                TokenRequestParam.CODE: code,
                TokenRequestParam.REDIRECT_URI: self.config.redirect_url,
                TokenRequestParam.CLIENT_ID: self.config.client_id,
                TokenRequestParam.CODE_VERIFIER: self._code_verifier,
            },
            headers=OAUTH_TOKEN_ENDPOINT_HEADERS,
            timeout=self.HTTP_REQUEST_TIMEOUT_SECONDS,
        )
        return self._handle_token_response(resp)

    def try_refresh_token_grant(self) -> Optional[str]:
        """Refresh token grant for public clients — no client_secret."""
        if not self._cached_token_data.refresh_token:
            return None

        try:
            resp = self._http_session.post(
                self.config.token_endpoint,
                data={
                    TokenRequestParam.GRANT_TYPE: GrantType.REFRESH_TOKEN,
                    TokenRequestParam.REFRESH_TOKEN: self._cached_token_data.refresh_token,
                    TokenRequestParam.CLIENT_ID: self.config.client_id,
                },
                headers=OAUTH_TOKEN_ENDPOINT_HEADERS,
                timeout=self.HTTP_REQUEST_TIMEOUT_SECONDS,
            )
            return self._handle_token_response(resp)
        except requests.HTTPError as e:
            status_code = getattr(getattr(e, "response", None), "status_code", None)
            # Only the HTTP status code is logged here, never a token value.
            # nosemgrep: python-logger-credential-disclosure
            logger.debug(
                "PKCE refresh-token grant rejected (http_status=%s); falling back to full auth flow",
                status_code,
            )
            if status_code in (HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                # Clear the refresh token by creating a new CachedToken without it
                self._cached_token_data = CachedToken()
            return None
        except Exception as e:
            # Only the exception type name is logged here, never a token value.
            # nosemgrep: python-logger-credential-disclosure
            logger.debug(
                "PKCE refresh-token grant failed (%s); falling back to full auth flow",
                type(e).__name__,
            )
            return None
