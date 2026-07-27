# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for connector module"""

import pytest
from unittest.mock import Mock, patch
from workday_ldq.connector import create_connection
from workday_ldq.auth_jwt_bearer_grant import JwtBearerAuth
from workday_ldq.auth_code_grant import AuthCodeGrantAuth
from workday_ldq.config import LDQConfig
from workday_ldq.driver_property import DriverProperty


@pytest.fixture
def mock_config():
    props = {
        DriverProperty.TOKEN_ENDPOINT:   "https://example.com/token",
        DriverProperty.CLIENT_ID:        "client123",
        DriverProperty.ISU:              "testuser",
        DriverProperty.PRIVATE_KEY:      "test_key",
        DriverProperty.HOST:             "example.myworkday.com",
        DriverProperty.PORT:             "443",
        DriverProperty.CATALOG:          "workday_core",
        DriverProperty.SCHEMA:           "public",
    }
    return LDQConfig(props)


@patch('workday_ldq.connector.trino.dbapi.connect')
def test_create_connection(mock_connect, mock_config):
    """Test connection creation"""
    mock_conn = Mock()
    mock_connect.return_value = mock_conn

    conn = create_connection(mock_config)

    assert conn == mock_conn

    # Verify trino.dbapi.connect was called with correct parameters
    mock_connect.assert_called_once()
    call_kwargs = mock_connect.call_args[1]

    assert call_kwargs['host'] == 'example.myworkday.com'
    assert call_kwargs['port'] == 443
    assert call_kwargs['catalog'] == 'workday_core'
    assert call_kwargs['schema'] == 'public'
    assert call_kwargs['http_scheme'] == 'https'
    assert isinstance(call_kwargs["auth"], JwtBearerAuth)


@pytest.fixture
def mock_auth_code_config():
    props = {
        # Verify model is not case-sensitive
        DriverProperty.AUTH_MODEL:              "aUtHoRiZaTiOn_CoDe",
        DriverProperty.TOKEN_ENDPOINT:          "https://example.myworkday.com/oauth/token",
        DriverProperty.AUTHORIZATION_ENDPOINT:  "https://example.myworkday.com/oauth/authorize",
        DriverProperty.REDIRECT_URL:            "https://localhost:8888/callback",
        DriverProperty.CLIENT_ID:               "client123",
        DriverProperty.CLIENT_SECRET:           "client-secret",
        DriverProperty.HOST:                    "example.myworkday.com",
        DriverProperty.PORT:                    "443",
        DriverProperty.CATALOG:                 "workday_core",
        DriverProperty.SCHEMA:                  "public",
    }
    return props


@patch('workday_ldq.connector.trino.dbapi.connect')
def test_create_connection_auth_code(mock_connect, mock_auth_code_config):
    mock_conn = Mock()
    mock_connect.return_value = mock_conn

    conn = create_connection(mock_auth_code_config)
    assert conn == mock_conn

    call_kwargs = mock_connect.call_args[1]
    assert call_kwargs["http_scheme"] == "https"
    assert isinstance(call_kwargs["auth"], AuthCodeGrantAuth)


@patch('workday_ldq.connector.trino.dbapi.connect')
def test_http_timeout_default_value(mock_connect, mock_config):
    """Test that http_timeout uses default value of 30 when not specified"""
    mock_conn = Mock()
    mock_connect.return_value = mock_conn

    conn = create_connection(mock_config)

    assert conn == mock_conn

    call_kwargs = mock_connect.call_args[1]
    assert call_kwargs['request_timeout'] == 30


@patch('workday_ldq.connector.trino.dbapi.connect')
def test_http_timeout_custom_value(mock_connect):
    """Test that http_timeout can be configured via wd.http.timeout property"""
    props = {
        DriverProperty.TOKEN_ENDPOINT:      "https://example.com/token",
        DriverProperty.CLIENT_ID:           "client123",
        DriverProperty.ISU:                 "testuser",
        DriverProperty.PRIVATE_KEY:         "test_key",
        DriverProperty.HOST:                "example.myworkday.com",
        DriverProperty.HTTP_REQUEST_TIMEOUT: "120",
    }
    config = LDQConfig(props)

    mock_conn = Mock()
    mock_connect.return_value = mock_conn

    conn = create_connection(config)

    assert conn == mock_conn

    call_kwargs = mock_connect.call_args[1]
    assert call_kwargs['request_timeout'] == 120


@patch('workday_ldq.connector.trino.dbapi.connect')
def test_session_properties_not_passed_when_not_specified(mock_connect, mock_config):
    """Test that session_properties is not passed to Trino when not specified"""
    mock_conn = Mock()
    mock_connect.return_value = mock_conn

    conn = create_connection(mock_config)

    assert conn == mock_conn

    call_kwargs = mock_connect.call_args[1]
    assert 'session_properties' not in call_kwargs


@patch('workday_ldq.connector.trino.dbapi.connect')
def test_session_properties_passed_when_specified(mock_connect):
    """Test that session_properties are passed to Trino when specified"""
    props = {
        DriverProperty.TOKEN_ENDPOINT:      "https://example.com/token",
        DriverProperty.CLIENT_ID:           "client123",
        DriverProperty.ISU:                 "testuser",
        DriverProperty.PRIVATE_KEY:         "test_key",
        DriverProperty.HOST:                "example.myworkday.com",
        DriverProperty.SESSION_PROPERTIES:  "query_max_run_time=1h,join_distribution_type=broadcast",
    }
    config = LDQConfig(props)

    mock_conn = Mock()
    mock_connect.return_value = mock_conn

    conn = create_connection(config)

    assert conn == mock_conn

    call_kwargs = mock_connect.call_args[1]
    assert 'session_properties' in call_kwargs
    assert call_kwargs['session_properties'] == {
        "query_max_run_time": "1h",
        "join_distribution_type": "broadcast",
    }
