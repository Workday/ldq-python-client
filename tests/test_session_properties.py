# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Test session_properties parsing and validation."""

import pytest

from workday_ldq.config import LDQConfig
from workday_ldq.driver_property import DriverProperty


# Minimal valid config for testing
MINIMAL_CONFIG = {
    DriverProperty.AUTH_MODEL: "jwt_bearer",
    DriverProperty.TOKEN_ENDPOINT: "https://example.com/token",
    DriverProperty.CLIENT_ID: "test_client",
    DriverProperty.ISU: "test_isu",
    DriverProperty.PRIVATE_KEY: "fake-key-for-testing",
}


class TestSessionPropertiesValid:
    """Valid session property formats."""

    def test_none_when_not_specified(self):
        """Returns None if SESSION_PROPERTIES not set."""
        config = LDQConfig(MINIMAL_CONFIG)
        assert config.session_properties is None

    def test_empty_string_returns_none(self):
        """Empty string returns None."""
        cfg_dict = {**MINIMAL_CONFIG, DriverProperty.SESSION_PROPERTIES: ""}
        config = LDQConfig(cfg_dict)
        assert config.session_properties is None

    def test_single_property(self):
        """Single key=value pair."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "query_max_run_time=1h",
        }
        config = LDQConfig(cfg_dict)
        assert config.session_properties == {"query_max_run_time": "1h"}

    def test_multiple_properties(self):
        """Multiple comma-separated properties."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "query_max_run_time=1h,join_distribution_type=broadcast",
        }
        config = LDQConfig(cfg_dict)
        assert config.session_properties == {
            "query_max_run_time": "1h",
            "join_distribution_type": "broadcast",
        }

    def test_value_with_special_characters(self):
        """Value containing special characters (@ and .) is handled correctly."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "comment=tested@example.com",
        }
        config = LDQConfig(cfg_dict)
        assert config.session_properties == {"comment": "tested@example.com"}

    def test_whitespace_trimming(self):
        """Whitespace around keys/values is trimmed."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "  join_distribution_type  =  broadcast  ,  query_max_run_time  =  1h  ",
        }
        config = LDQConfig(cfg_dict)
        assert config.session_properties == {"join_distribution_type": "broadcast", "query_max_run_time": "1h"}

    def test_trailing_comma(self):
        """Trailing comma is skipped gracefully."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "query_max_run_time=1h,",
        }
        config = LDQConfig(cfg_dict)
        assert config.session_properties == {"query_max_run_time": "1h"}

    def test_leading_comma(self):
        """Leading comma is skipped gracefully."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: ",query_max_run_time=1h",
        }
        config = LDQConfig(cfg_dict)
        assert config.session_properties == {"query_max_run_time": "1h"}

    def test_multiple_empty_pairs(self):
        """Multiple empty pairs are skipped."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: ",,query_max_run_time=1h,,",
        }
        config = LDQConfig(cfg_dict)
        assert config.session_properties == {"query_max_run_time": "1h"}


class TestSessionPropertiesErrors:
    """Invalid session property formats should raise RuntimeError."""

    def test_malformed_no_equals(self):
        """Pair without '=' raises RuntimeError."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "join_distribution_type",
        }
        config = LDQConfig(cfg_dict)
        with pytest.raises(RuntimeError, match="Invalid session property format"):
            _ = config.session_properties

    def test_malformed_mixed_valid_invalid(self):
        """One invalid pair among valid pairs raises RuntimeError."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "key1=value1,no_equals_here,key2=value2",
        }
        config = LDQConfig(cfg_dict)
        with pytest.raises(RuntimeError, match="Invalid session property format"):
            _ = config.session_properties

    def test_empty_key(self):
        """Empty key raises RuntimeError."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "=1h",
        }
        config = LDQConfig(cfg_dict)
        with pytest.raises(RuntimeError, match="key cannot be empty"):
            _ = config.session_properties

    def test_empty_value(self):
        """Empty value raises RuntimeError."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "query_max_run_time=",
        }
        config = LDQConfig(cfg_dict)
        with pytest.raises(RuntimeError, match="value cannot be empty"):
            _ = config.session_properties

    def test_whitespace_only_key(self):
        """Whitespace-only key raises RuntimeError."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "   =1h",
        }
        config = LDQConfig(cfg_dict)
        with pytest.raises(RuntimeError, match="key cannot be empty"):
            _ = config.session_properties

    def test_whitespace_only_value(self):
        """Whitespace-only value raises RuntimeError."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "query_max_run_time=   ",
        }
        config = LDQConfig(cfg_dict)
        with pytest.raises(RuntimeError, match="value cannot be empty"):
            _ = config.session_properties

    def test_error_includes_position(self):
        """Error message includes position of bad pair."""
        cfg_dict = {
            **MINIMAL_CONFIG,
            DriverProperty.SESSION_PROPERTIES: "key1=value1,bad_pair,key2=value2",
        }
        config = LDQConfig(cfg_dict)
        with pytest.raises(RuntimeError, match="position 1"):
            _ = config.session_properties
