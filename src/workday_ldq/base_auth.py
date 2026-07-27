# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Shared base class for Workday Live Data Query (LDQ) OAuth 2.0 authentication"""

import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import NamedTuple, Optional
from urllib.parse import urlparse, urlunparse

import jwt
import requests
from trino.auth import Authentication
from trino.constants import HEADER_EXTRA_CREDENTIAL

from .constants import (
    HTTPHeader,
    TokenParam,
    JWTClaim,
    DEFAULT_EARLY_REFRESH_SKEW_SECONDS,
    DEFAULT_TOKEN_EXPIRATION_SECONDS,
    DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS,
    LDQ_GATEWAY_PATH_PREFIX,
)
from .http_client import create_oauth_http_session

logger = logging.getLogger(__name__)


class CachedToken(NamedTuple):
    """Immutable container for OAuth token data."""
    access_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    refresh_token: Optional[str] = None


class BaseAuth(Authentication, ABC):
    """
    Abstract base class for OAuth 2.0 authentication handlers.

    Provides shared token caching, header injection, and request interception.
    Subclasses must implement get_new_access_token() with their specific grant flow.
    """

    HTTP_REQUEST_TIMEOUT_SECONDS = DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS

    def __init__(self, config) -> None:
        self.config = config
        self._cached_token_data = CachedToken()
        # Lock to prevent concurrent token refresh attempts (avoids multiple browser popups)
        self._token_lock = threading.Lock()
        # This enables connection pooling and automatic retries across all OAuth token requests
        self._http_session = create_oauth_http_session()

    def get_token(self) -> str:
        """Return a valid access token, using refresh token when possible.

        Uses a lock to prevent concurrent refresh attempts (which could cause
        multiple browser popups in AuthCodeGrantAuth).
        """
        # Fast path: if token is valid, return immediately without acquiring lock
        if self._is_token_valid():
            if self._cached_token_data.access_token is None:
                raise RuntimeError("Token validation passed but access_token is None")
            return self._cached_token_data.access_token

        # Slow path: acquire lock to refresh token
        with self._token_lock:
            # Double-check: another thread may have refreshed while we waited for lock
            if self._is_token_valid():
                if self._cached_token_data.access_token is None:
                    raise RuntimeError("Token validation passed but access_token is None")
                return self._cached_token_data.access_token
            # Try refresh token first if available
            refreshed = self.try_refresh_token_grant()
            if refreshed:
                return refreshed

            # Fall back to full authentication flow
            return self.get_new_access_token()

    @abstractmethod
    def try_refresh_token_grant(self) -> Optional[str]:
        """
        Try to refresh access token using cached refresh token.
        Returns new access token on success, None on failure.

        Subclasses should return None if they don't support refresh tokens.
        """
        pass

    @abstractmethod
    def get_new_access_token(self) -> str:
        """Obtain a new access token using the grant-specific flow."""
        ...

    @staticmethod
    def _set_auth_headers(http_session, token: str) -> None:
        try:
            decoded = jwt.decode_complete(token, options={"verify_signature": False})
            tenant = decoded["payload"].get(JWTClaim.TENANT)
            if not tenant or not tenant.strip():
                raise ValueError("Tenant claim is missing or empty in access token")
        except Exception as e:
            raise ValueError(f"Error parsing JWT access token: {e}") from e

        http_session.headers[HTTPHeader.AUTHORIZATION] = f"Bearer {token}"
        http_session.headers[HTTPHeader.TENANT] = tenant
        http_session.headers[HEADER_EXTRA_CREDENTIAL] = f"token={token}"

    def set_http_session(self, http_session) -> None:
        """Configure HTTP session with authentication headers and request interceptor."""
        token = self.get_token()
        self._set_auth_headers(http_session, token)

        original_request = http_session.request

        def intercepted_request(method, url, **kwargs):
            """
            Intercept and modify requests:
            1. Rewrite host/port from config
            2. Prepend /dataservice gateway path prefix when absent
            3. On 401: force-refresh token and retry once
            """
            parsed = urlparse(url)
            netloc = f"{self.config.host}:{self.config.port}"
            has_gateway_prefix = parsed.path.startswith(LDQ_GATEWAY_PATH_PREFIX)
            path = parsed.path if has_gateway_prefix else LDQ_GATEWAY_PATH_PREFIX + parsed.path
            modified_url = urlunparse(parsed._replace(netloc=netloc, path=path))

            response = original_request(method, modified_url, **kwargs)
            if response.status_code == HTTPStatus.UNAUTHORIZED:
                try:
                    response.close()
                except Exception:
                    pass
                with self._token_lock:
                    # Clear cached token data on 401
                    self._cached_token_data = self._cached_token_data._replace(access_token=None, expires_at=None)

                newly_acquired_token = self.get_token()
                self._set_auth_headers(http_session, newly_acquired_token)
                response = original_request(method, modified_url, **kwargs)

            return response

        http_session.request = intercepted_request

    def _is_token_valid(self) -> bool:
        """Check if cached token is still valid (with 5-minute safety buffer)."""
        if not self._cached_token_data.access_token or not self._cached_token_data.expires_at:
            return False
        # Use 5-minute buffer (300 seconds) to reduce risk of token expiring mid-request
        # This matches the Java driver's DEFAULT_EARLY_REFRESH_SKEW_MIN
        return datetime.now(timezone.utc) < (
                self._cached_token_data.expires_at - timedelta(seconds=DEFAULT_EARLY_REFRESH_SKEW_SECONDS))

    def _cache_token_response(self, data: dict) -> str:
        """Parse token endpoint response, cache tokens, and return access token."""
        access_token = data.get(TokenParam.ACCESS_TOKEN)
        if not access_token:
            raise ValueError(
                f"Token endpoint response missing '{TokenParam.ACCESS_TOKEN}'."
            )

        expires_in = data.get(TokenParam.EXPIRES_IN, DEFAULT_TOKEN_EXPIRATION_SECONDS)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        # Cache refresh token only when the server provides one.
        # Many OAuth providers omit `refresh_token` on refresh unless they rotate it;
        # in that case we must preserve the previously cached refresh token.
        refresh_token = data.get(TokenParam.REFRESH_TOKEN)
        if not refresh_token:
            # Preserve existing refresh token if server didn't provide a new one
            refresh_token = self._cached_token_data.refresh_token

        # Create new immutable CachedToken tuple
        self._cached_token_data = CachedToken(
            access_token=access_token,
            expires_at=expires_at,
            refresh_token=refresh_token
        )

        return access_token

    def _handle_token_response(self, resp: requests.Response) -> str:
        """Raise on HTTP error (with body in message) and cache the token response."""
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_err:
            # Include response body in error message (contains error/error_description)
            raise requests.HTTPError(
                f"Token endpoint returned {resp.status_code}: {resp.text}",
                response=resp
            ) from http_err
        return self._cache_token_response(resp.json())
