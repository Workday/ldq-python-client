# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Configuration helpers for the Workday Live Data Query (LDQ) connector."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from trino.auth import Authentication

from trino.constants import DEFAULT_REQUEST_TIMEOUT

from .auth_model import AuthModel
from .driver_property import DriverProperty


# ---------------------------------------------------------------------------
# Properties file parser
# ---------------------------------------------------------------------------

def _parse_properties_file(path: Path) -> Dict[str, str]:
    """Parse a Java-style .properties file, supporting multi-line values."""
    properties: Dict[str, str] = {}
    current_key: Optional[str] = None
    current_value: List[str] = []

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.strip().startswith('#'):
                continue
            if '=' in line and not line.startswith(' '):
                if current_key:
                    properties[current_key] = '\n'.join(current_value)
                key, value = line.split('=', 1)
                current_key = key.strip()
                current_value = [value.strip()]
            elif current_key:
                current_value.append(line.strip())

    if current_key:
        properties[current_key] = '\n'.join(current_value)

    return properties


# ---------------------------------------------------------------------------
# Configuration class
# ---------------------------------------------------------------------------

class LDQConfig:
    """Configuration for LDQ connections (JWT_BEARER, AUTHORIZATION_CODE, AUTHORIZATION_CODE_PKCE)."""

    _properties: Dict[str, str]
    _auth_model: AuthModel

    def __init__(self, properties: Dict[str, str]) -> None:
        self._properties = dict(properties)
        self._auth_model = AuthModel.from_string(self._properties.get(DriverProperty.AUTH_MODEL))
        # Set the resolved auth model back into properties if it wasn't explicitly set
        if DriverProperty.AUTH_MODEL not in self._properties:
            self._properties[DriverProperty.AUTH_MODEL] = self._auth_model.name
        self._validate()

    @classmethod
    def from_file(cls, filepath: str) -> LDQConfig:
        """Load configuration from a Java-style .properties file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Properties file not found: {filepath}")
        return cls(_parse_properties_file(path))

    @property
    def properties(self) -> Dict[str, str]:
        return dict(self._properties)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._properties.get(key, default)

    def get_bool(self, key: str, default: bool = True) -> bool:
        value = self._properties.get(key)
        if value is None:
            return default
        return value.lower() in ("true", "1", "yes")

    def get_int(self, key: str, default: int) -> int:
        value = self._properties.get(key)
        return int(value) if value else default

    def get_float(self, key: str, default: float) -> float:
        value = self._properties.get(key)
        return float(value) if value else default

    def _require(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise RuntimeError(f"{key} missing — should have been caught by _validate()")
        return value

    @property
    def auth_model(self) -> AuthModel:
        return self._auth_model

    def create_authentication(self) -> Authentication:
        """Create the Trino Authentication implementation for this config."""
        return self.auth_model.auth_class(self)

    def _validate(self) -> None:
        self.auth_model.validator(self)

    # ------------------------------------------------------------------
    # Typed property accessors
    # ------------------------------------------------------------------

    @property
    def token_endpoint(self) -> str:
        return self._require(DriverProperty.TOKEN_ENDPOINT)

    @property
    def client_id(self) -> str:
        return self._require(DriverProperty.CLIENT_ID)

    @property
    def host(self) -> str:
        return self.get(DriverProperty.HOST) or "localhost"

    @property
    def port(self) -> int:
        return self.get_int(DriverProperty.PORT, 443)

    @property
    def http_timeout(self) -> float:
        """HTTP request timeout in seconds (default: 30)."""
        return self.get_float(DriverProperty.HTTP_REQUEST_TIMEOUT, DEFAULT_REQUEST_TIMEOUT)

    @property
    def catalog(self) -> str:
        return self.get(DriverProperty.CATALOG) or "workday_core"

    @property
    def schema(self) -> str:
        return self.get(DriverProperty.SCHEMA) or "public"

    @property
    def isu(self) -> str:
        return self._require(DriverProperty.ISU)

    @property
    def private_key(self) -> str:
        # Inline key takes priority; falls back to reading PRIVATE_KEY_FILE
        inline_key = self.get(DriverProperty.PRIVATE_KEY)
        if inline_key:
            return inline_key
        key_file_path = self.get(DriverProperty.PRIVATE_KEY_FILE)
        if key_file_path:
            key_path = Path(key_file_path)
            if not key_path.exists():
                raise FileNotFoundError(f"Private key file not found: {key_file_path}")
            with open(key_path, 'r', encoding='utf-8') as f:
                return f.read()
        raise ValueError("No private key or private key file configured")

    @property
    def authorization_endpoint(self) -> str:
        return self._require(DriverProperty.AUTHORIZATION_ENDPOINT)

    @property
    def redirect_url(self) -> str:
        return self._require(DriverProperty.REDIRECT_URL)

    @property
    def client_secret(self) -> str:
        return self._require(DriverProperty.CLIENT_SECRET)

    @property
    def session_properties(self) -> Optional[Dict[str, str]]:
        """Trino session properties (optional).

        Format: comma-separated key=value pairs
        Example: "query_max_run_time=1h,join_distribution_type=broadcast"
        Returns None if not specified.

        Raises:
            RuntimeError: If format is invalid (malformed pair, empty key/value, etc.)
        """
        value = self.get(DriverProperty.SESSION_PROPERTIES)
        if not value:
            return None

        result: Dict[str, str] = {}
        for idx, pair in enumerate(value.split(',')):
            pair = pair.strip()

            if not pair:
                continue

            if '=' not in pair:
                raise RuntimeError(
                    f"Invalid session property format at position {idx}: {pair!r} "
                    f"(expected 'key=value')"
                )

            key, val = pair.split('=', 1)
            key = key.strip()
            val = val.strip()

            if not key:
                raise RuntimeError(
                    f"Session property key cannot be empty (pair {idx}): {pair!r}"
                )

            if not val:
                raise RuntimeError(
                    f"Session property value cannot be empty for key {key!r} (pair {idx})"
                )

            result[key] = val

        return result if result else None
