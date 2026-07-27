# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""OAuth 2.0 JWT Bearer authentication for Workday Live Data Query (LDQ)"""

import time
import uuid
from typing import Optional

import jwt

from .base_auth import BaseAuth
from .constants import (
    GrantType,
    TokenRequestParam,
    JWTAlgorithm,
    JWTClaim,
    OAUTH_TOKEN_ENDPOINT_HEADERS,
)


class JwtBearerAuth(BaseAuth):
    """
    LDQ authentication handler using JWT Bearer grant.

    Flow:
        1. Create JWT assertion signed with private key
        2. Exchange JWT for OAuth access token
        3. Cache token and reuse until near expiration
        4. Inject token into HTTP requests as Bearer token, see BaseAuth

    Note: JWT Bearer grant does not support refresh tokens.
    """

    def get_new_access_token(self) -> str:
        now = int(time.time())
        payload = {
            JWTClaim.ISS: self.config.client_id,  # Issuer
            JWTClaim.SUB: self.config.isu,  # Subject (ISU)
            JWTClaim.AUD: self.config.token_endpoint,  # Audience
            JWTClaim.IAT: now,  # Issued at
            JWTClaim.EXP: now + 300,  # Expires (5 min)
            JWTClaim.JTI: str(uuid.uuid4()),  # JWT ID (unique)
        }
        assertion = jwt.encode(payload, self.config.private_key, algorithm=JWTAlgorithm.RS256)

        resp = self._http_session.post(
            self.config.token_endpoint,
            data={
                TokenRequestParam.GRANT_TYPE: GrantType.JWT_BEARER,
                TokenRequestParam.ASSERTION: assertion,
            },
            headers=OAUTH_TOKEN_ENDPOINT_HEADERS,
            timeout=self.HTTP_REQUEST_TIMEOUT_SECONDS,
        )
        return self._handle_token_response(resp)

    def try_refresh_token_grant(self) -> Optional[str]:
        """JWT Bearer grant does not support refresh tokens."""
        return None
