# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Constants for Workday Live Data Query (LDQ) OAuth authentication.

This module contains OAuth 2.0 string constants used across the authentication modules.
All constants follow RFC 6749 (OAuth 2.0) and RFC 7519 (JWT) specifications.
"""
from __future__ import annotations

import os
from enum import Enum

# ---------------------------------------------------------------------------
# OAuth HTTP Client Configuration (property name + default, paired per knob)
# ---------------------------------------------------------------------------


class _ConfigProperty:

    def __init__(self, prop_name: str, default: int | float | bool):
        self.prop_name = prop_name
        self.default = default

    def resolve(self) -> str:
        """Return this knob's env var value, or its stringified default if unset."""
        return os.environ.get(self.prop_name, str(self.default))


class ConnectionRetry(_ConfigProperty, Enum):
    """OAuth retry configuration: env var property name paired with its default.

    These requests run while BaseAuth._token_lock is held (see base_auth.py), so every
    concurrent caller of get_token() blocks for as long as a single token request's retries
    take. Defaults are kept small for that reason; raising them via env var trades a longer
    worst-case lock hold time for more resilience against transient token-endpoint errors.
    """

    MAX_RETRIES = ("wd.oauth.retry.max-retries", 1)
    BACKOFF_MULTIPLIER = ("wd.oauth.retry.backoff-multiplier", 2.0)
    MAX_DELAY_SEC = ("wd.oauth.retry.max-delay-sec", 3)  # 3 seconds

    # Python-specific: Jitter configuration (not in Java)
    BACKOFF_JITTER = ("wd.oauth.retry.backoff-jitter", True)

# ---------------------------------------------------------------------------
# HTTP Status Codes for Retry
# ---------------------------------------------------------------------------

# Status codes that trigger automatic retry
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]

# ---------------------------------------------------------------------------
# Connection Pool Configuration
# ---------------------------------------------------------------------------

# Connection pool settings
DEFAULT_POOL_CONNECTIONS = 10
DEFAULT_POOL_MAXSIZE = 10

# ---------------------------------------------------------------------------
# HTTP Headers
# ---------------------------------------------------------------------------


class HTTPHeader:
    AUTHORIZATION = "Authorization"
    CONTENT_TYPE = "Content-Type"
    TENANT = "X-Tenant"
    ACCEPT = "Accept"


# ---------------------------------------------------------------------------
# OAuth 2.0 Grant Types (RFC 6749)
# ---------------------------------------------------------------------------


class GrantType:
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


# ---------------------------------------------------------------------------
# OAuth 2.0 Token Endpoint Parameters (RFC 6749 §5.1)
# ---------------------------------------------------------------------------


class TokenRequestParam:
    GRANT_TYPE = "grant_type"
    CODE = "code"
    REDIRECT_URI = "redirect_uri"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"
    REFRESH_TOKEN = "refresh_token"
    ASSERTION = "assertion"
    CODE_VERIFIER = "code_verifier"  # RFC 7636 (PKCE)


class TokenParam:
    ACCESS_TOKEN = "access_token"
    EXPIRES_IN = "expires_in"
    REFRESH_TOKEN = "refresh_token"
    ERROR = "error"
    ERROR_DESCRIPTION = "error_description"


# ---------------------------------------------------------------------------
# OAuth 2.0 Authorization Endpoint Parameters (RFC 6749 §4.1.1)
# ---------------------------------------------------------------------------


class AuthzParam:
    RESPONSE_TYPE = "response_type"
    CLIENT_ID = "client_id"
    REDIRECT_URI = "redirect_uri"
    STATE = "state"
    CODE = "code"
    CODE_CHALLENGE = "code_challenge"  # RFC 7636 (PKCE)
    CODE_CHALLENGE_METHOD = "code_challenge_method"  # RFC 7636 (PKCE)


class AuthzResponseType:
    CODE = "code"


# ---------------------------------------------------------------------------
# PKCE Implementation Constants (RFC 7636)
# ---------------------------------------------------------------------------

PKCE_CODE_VERIFIER_BYTE_LENGTH = 64  # 64 bytes = 86 base64url chars (matches Java)
PKCE_CODE_CHALLENGE_METHOD = "S256"  # SHA-256 hash method

# ---------------------------------------------------------------------------
# OAuth Token Endpoint Headers
# ---------------------------------------------------------------------------

OAUTH_TOKEN_ENDPOINT_HEADERS = {
    HTTPHeader.CONTENT_TYPE: "application/x-www-form-urlencoded",
    HTTPHeader.ACCEPT: "application/json",
}


# ---------------------------------------------------------------------------
# JWT Constants (RFC 7519)
# ---------------------------------------------------------------------------


class JWTHeader:
    ALG = "alg"  # Algorithm
    TYP = "typ"  # Type


class JWTAlgorithm:
    RS256 = "RS256"  # RSA Signature with SHA-256


class JWTClaim:
    # Standard claims (RFC 7519)
    ISS = "iss"  # Issuer
    SUB = "sub"  # Subject
    AUD = "aud"  # Audience
    IAT = "iat"  # Issued At
    EXP = "exp"  # Expiration Time
    JTI = "jti"  # JWT ID
    # Workday-specific
    TENANT = "tenant"  # Tenant identification


class JWTType:
    JWT = "JWT"


# ---------------------------------------------------------------------------
# Token Timing Constants
# ---------------------------------------------------------------------------

# Early refresh buffer (seconds) - refresh token this many seconds before expiration
DEFAULT_EARLY_REFRESH_SKEW_SECONDS = 300  # 5 minutes

# Default token expiration when server doesn't provide expires_in
DEFAULT_TOKEN_EXPIRATION_SECONDS = 3600  # 1 hour

# Default timeout for callback server (seconds)
DEFAULT_CALLBACK_TIMEOUT_SECONDS = 180

# ---------------------------------------------------------------------------
# HTTP Request Timeouts
# ---------------------------------------------------------------------------

# Default timeout for OAuth token requests (seconds)
DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS = 30

# ---------------------------------------------------------------------------
# Path Prefix Constants
# ---------------------------------------------------------------------------

LDQ_GATEWAY_PATH_PREFIX = "/dataservice"

HTTP_METHOD_POST = "POST"
HTTPS_SCHEME = "https://"
HTTP_SCHEME = "http://"
