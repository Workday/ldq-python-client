# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""AuthModel enum for the Workday Live Data Query (LDQ) connector."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from .constants import HTTPS_SCHEME

if TYPE_CHECKING:
    from .config import LDQConfig

from .auth_code_grant import AuthCodeGrantAuth
from .auth_code_pkce_grant import AuthCodeGrantPKCEAuth
from .auth_jwt_bearer_grant import JwtBearerAuth
from .callback_server import _validate_redirect_url
from .driver_property import DriverProperty

# ---------------------------------------------------------------------------
# Required property lists — owned by AuthModel members.
# ---------------------------------------------------------------------------

_JWT_REQUIRED = [DriverProperty.TOKEN_ENDPOINT, DriverProperty.CLIENT_ID, DriverProperty.ISU]
_AUTH_CODE_PKCE_REQUIRED = [DriverProperty.TOKEN_ENDPOINT, DriverProperty.CLIENT_ID,
                            DriverProperty.AUTHORIZATION_ENDPOINT, DriverProperty.REDIRECT_URL]
_AUTH_CODE_REQUIRED = _AUTH_CODE_PKCE_REQUIRED + [DriverProperty.CLIENT_SECRET]


# ---------------------------------------------------------------------------
# Validators — defined before AuthModel so enum members can reference them.
# LDQConfig is imported under TYPE_CHECKING only; no runtime cycle.
# ---------------------------------------------------------------------------

def _validate_jwt_bearer(cfg: LDQConfig) -> None:
    missing = [prop for prop in cfg.auth_model.required_properties if not cfg.get(prop)]
    if missing:
        raise ValueError(f"Missing required properties for JWT_BEARER: {', '.join(missing)}")
    if not cfg.get(DriverProperty.PRIVATE_KEY) and not cfg.get(DriverProperty.PRIVATE_KEY_FILE):
        raise ValueError(
            f"Either '{DriverProperty.PRIVATE_KEY}' or '{DriverProperty.PRIVATE_KEY_FILE}' must be provided"
        )


def _validate_auth_code_endpoints(cfg: LDQConfig) -> None:
    """Shared HTTPS + redirect URL validation for auth-code-based models."""
    if not (cfg.get(DriverProperty.TOKEN_ENDPOINT) or "").startswith(HTTPS_SCHEME):
        raise ValueError(f"{DriverProperty.TOKEN_ENDPOINT} must use HTTPS")
    if not (cfg.get(DriverProperty.AUTHORIZATION_ENDPOINT) or "").startswith("%s" % HTTPS_SCHEME):
        raise ValueError(f"{DriverProperty.AUTHORIZATION_ENDPOINT} must use HTTPS")
    _validate_redirect_url(urlparse(cfg.get(DriverProperty.REDIRECT_URL) or ""))


def _validate_auth_code_base(cfg: LDQConfig) -> None:
    missing = [prop for prop in cfg.auth_model.required_properties if not cfg.get(prop)]
    if missing:
        raise ValueError(f"Missing required properties for {cfg.auth_model.name}: {', '.join(missing)}")
    _validate_auth_code_endpoints(cfg)


# ---------------------------------------------------------------------------
# AuthModel enum
# Each member carries its auth class, validator, and required properties —
# adding a new model only requires a new enum entry (OCP).
# ---------------------------------------------------------------------------

class AuthModel(str, Enum):
    """Supported authentication models for Workday Live Data Query (LDQ)."""

    def __new__(cls, value: str, auth_class: type, validator, required_properties: list) -> AuthModel:
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.auth_class = auth_class
        obj.validator = validator
        obj.required_properties = required_properties
        return obj

    @classmethod
    def from_string(cls, raw: Optional[str], default: Optional[AuthModel] = None) -> AuthModel:
        """Resolve a raw string to an AuthModel member (case-insensitive)."""
        if default is None:
            default = cls.JWT_BEARER
        if raw is None or not raw.strip():
            return default
        value = raw.strip().upper()
        for model in cls:
            if model.name == value:
                return model
        known = "', '".join(m.name for m in cls)
        raise ValueError(f"Unsupported wd.authn.authModel: {raw!r} (expected one of '{known}')")

    JWT_BEARER = ("jwt_bearer", JwtBearerAuth, _validate_jwt_bearer, _JWT_REQUIRED)
    AUTHORIZATION_CODE = ("authorization_code", AuthCodeGrantAuth, _validate_auth_code_base, _AUTH_CODE_REQUIRED)
    AUTHORIZATION_CODE_PKCE = (
        "authorization_code_pkce", AuthCodeGrantPKCEAuth, _validate_auth_code_base, _AUTH_CODE_PKCE_REQUIRED)


# Convenient aliases
JWT_BEARER = AuthModel.JWT_BEARER
AUTHORIZATION_CODE = AuthModel.AUTHORIZATION_CODE
AUTHORIZATION_CODE_PKCE = AuthModel.AUTHORIZATION_CODE_PKCE
