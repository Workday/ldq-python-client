# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Pre-issued access token authentication for Workday Live Data Query (LDQ)"""

from datetime import datetime, timezone
from typing import Optional

import jwt

from .base_auth import BaseAuth, CachedToken
from .constants import JWTClaim


class AccessTokenAuth(BaseAuth):
    """
    LDQ auth handler for Access Token/ Alpaca Token
    The token is used exactly as supplied: no token exchange is performed, and it is sent as a
    Bearer token with the tenant read from its ``tenant`` claim, see BaseAuth.
    The token must be a JWT carrying an ``exp`` claim.

    Note: refresh tokens are not supported. Supply a new access token and reconnect when it expires.
    """

    def get_new_access_token(self, trace_id: Optional[str] = None) -> str:
        token = self.config.access_token
        try:
            exp = jwt.decode(token, options={"verify_signature": False}).get(JWTClaim.EXP)
        except jwt.PyJWTError as e:
            raise ValueError("Failed to parse supplied access token as a JWT") from e
        if exp is None:
            raise ValueError("Supplied access token is missing an expiration (exp) claim")
        self._cached_token_data = CachedToken(
            access_token=token,
            expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
        )
        return token

    def try_refresh_token_grant(self, trace_id: Optional[str] = None) -> Optional[str]:
        return None
