# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for authentication module"""

import base64
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from trino.constants import HEADER_EXTRA_CREDENTIAL
from workday_ldq.auth_jwt_bearer_grant import JwtBearerAuth
from workday_ldq.auth_model import JWT_BEARER
from workday_ldq.base_auth import CachedToken
from workday_ldq.config import LDQConfig
from workday_ldq.constants import (
    HTTPHeader,
    TokenParam,
)
from workday_ldq.driver_property import DriverProperty


@pytest.fixture
def mock_config():
    props = {
        DriverProperty.TOKEN_ENDPOINT: "https://example.com/token",
        DriverProperty.CLIENT_ID: "client123",
        DriverProperty.ISU: "testuser",
        DriverProperty.PRIVATE_KEY: "fake-key-for-testing",
        DriverProperty.HOST: "example.myworkday.com",
    }
    return LDQConfig(props)


def test_auth_initialization(mock_config):
    auth = JwtBearerAuth(mock_config)

    assert auth.config == mock_config
    # Verify auth model defaults to JWT_BEARER when not explicitly set
    assert mock_config.auth_model == JWT_BEARER
    assert mock_config.get(DriverProperty.AUTH_MODEL) == JWT_BEARER.name
    assert auth._cached_token_data.access_token is None
    assert auth._cached_token_data.expires_at is None


def test_token_caching(mock_config):
    auth = JwtBearerAuth(mock_config)

    assert not auth._is_token_valid()

    auth._cached_token_data = CachedToken(access_token="test_token", expires_at=datetime.now(timezone.utc) + timedelta(hours=1))

    assert auth._is_token_valid()

    auth._cached_token_data = auth._cached_token_data._replace(expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
    assert not auth._is_token_valid()


@patch('workday_ldq.auth_jwt_bearer_grant.jwt.encode')
def test_token_refresh(mock_jwt_encode, mock_config):
    mock_jwt_encode.return_value = "mocked_jwt_assertion"

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        TokenParam.ACCESS_TOKEN: "new_access_token",
        TokenParam.EXPIRES_IN: 3600
    }

    auth = JwtBearerAuth(mock_config)
    mock_post = Mock(return_value=mock_response)
    auth._http_session.post = mock_post
    token = auth.get_new_access_token()

    assert token == "new_access_token"
    assert auth._cached_token_data.access_token == "new_access_token"
    assert auth._cached_token_data.expires_at is not None

    mock_jwt_encode.assert_called_once()
    call_args = mock_jwt_encode.call_args
    assert call_args[1]['algorithm'] == 'RS256'

    mock_post.assert_called_once()
    assert mock_config.token_endpoint in str(mock_post.call_args)


@patch('workday_ldq.auth_jwt_bearer_grant.jwt.encode')
def test_set_http_headers(mock_jwt_encode, mock_config):
    # Create a valid JWT format: header.payload.signature
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({"tenant": "test_tenant"}).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip('=')
    mock_jwt_token = f"{header}.{payload}.{signature}"

    mock_jwt_encode.return_value = "mocked_jwt"
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        TokenParam.ACCESS_TOKEN: mock_jwt_token,
        TokenParam.EXPIRES_IN: 3600
    }

    auth = JwtBearerAuth(mock_config)
    auth._http_session.post = Mock(return_value=mock_response)

    mock_request = Mock()
    mock_request.headers = {}

    auth.set_http_session(mock_request)

    assert HTTPHeader.AUTHORIZATION in mock_request.headers
    assert mock_request.headers[HTTPHeader.AUTHORIZATION] == f"Bearer {mock_jwt_token}"
    assert HTTPHeader.TENANT in mock_request.headers
    assert mock_request.headers[HTTPHeader.TENANT] == "test_tenant"
    # Verify X-Trino-Extra-Credential header is set with token key (matching Java ACCESS_TOKEN_KEY)
    assert HEADER_EXTRA_CREDENTIAL in mock_request.headers
    assert mock_request.headers[HEADER_EXTRA_CREDENTIAL] == f"token={mock_jwt_token}"


@patch('workday_ldq.auth_jwt_bearer_grant.jwt.encode')
def test_401_retry_with_token_refresh(mock_jwt_encode, mock_config):
    """Test that 401 responses trigger token refresh and retry"""
    # Create valid JWT tokens
    def create_jwt_token(tenant_name):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({"tenant": tenant_name}).encode()).decode().rstrip('=')
        signature = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip('=')
        return f"{header}.{payload}.{signature}"

    initial_token = create_jwt_token("test_tenant")
    refreshed_token = create_jwt_token("test_tenant")

    mock_jwt_encode.return_value = "mocked_jwt"

    auth = JwtBearerAuth(mock_config)

    # First call returns initial token, second call returns refreshed token
    mock_post = Mock(side_effect=[
        Mock(status_code=200, json=lambda: {TokenParam.ACCESS_TOKEN: initial_token, TokenParam.EXPIRES_IN: 3600}),
        Mock(status_code=200, json=lambda: {TokenParam.ACCESS_TOKEN: refreshed_token, TokenParam.EXPIRES_IN: 3600})
    ])
    auth._http_session.post = mock_post

    # Track request calls - this will be the ORIGINAL request function
    request_call_count = 0
    original_responses = []

    def mock_request_func(method, url, **kwargs):
        nonlocal request_call_count
        request_call_count += 1

        response = Mock()
        if request_call_count == 1:
            # First request returns 401
            response.status_code = 401
            response.close = Mock()
        else:
            # Second request (after retry) returns 200
            response.status_code = 200

        original_responses.append(response)
        return response

    mock_session = Mock()
    mock_session.headers = {}
    mock_session.request = mock_request_func

    # This will wrap mock_request_func with the interceptor
    auth.set_http_session(mock_session)

    # Verify initial token is set
    assert mock_session.headers[HTTPHeader.AUTHORIZATION] == f"Bearer {initial_token}"

    # Make a request that will return 401, triggering retry
    # mock_session.request is now the intercepted_request function
    response = mock_session.request("GET", "http://example.com/api/test")

    # Verify:
    # 1. Request was made twice (initial + retry)
    assert request_call_count == 2

    # 2. First response was closed
    assert original_responses[0].close.called

    # 3. Final response is successful (200)
    assert response.status_code == 200

    # 4. All headers were updated with refreshed token (Authorization, X-Tenant, X-Trino-Extra-Credential)
    assert mock_session.headers[HTTPHeader.AUTHORIZATION] == f"Bearer {refreshed_token}"
    assert mock_session.headers[HTTPHeader.TENANT] == "test_tenant"
    assert mock_session.headers[HEADER_EXTRA_CREDENTIAL] == f"token={refreshed_token}"

    # 4. Token was refreshed (mock_post called twice)
    assert mock_post.call_count == 2

    # 5. Authorization header was updated with refreshed token
    assert mock_session.headers[HTTPHeader.AUTHORIZATION] == f"Bearer {refreshed_token}"


@patch('workday_ldq.auth_jwt_bearer_grant.jwt.encode')
def test_url_modification_with_prefix(mock_jwt_encode, mock_config):
    """Test that URLs are modified with host/port and /dataservice prefix"""
    # Create a valid JWT token
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({"tenant": "test_tenant"}).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip('=')
    mock_jwt_token = f"{header}.{payload}.{signature}"

    mock_jwt_encode.return_value = "mocked_jwt"
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        TokenParam.ACCESS_TOKEN: mock_jwt_token,
        TokenParam.EXPIRES_IN: 3600
    }

    auth = JwtBearerAuth(mock_config)
    auth._http_session.post = Mock(return_value=mock_response)

    # Track URLs passed to the ORIGINAL request function (after interception)
    captured_urls = []

    def mock_request_func(method, url, **kwargs):
        captured_urls.append(url)
        response = Mock()
        response.status_code = 200
        return response

    mock_session = Mock()
    mock_session.headers = {}
    mock_session.request = mock_request_func

    # This wraps mock_request_func with the interceptor
    auth.set_http_session(mock_session)

    # Make a request - mock_session.request is now the interceptor
    mock_session.request("GET", "http://original-host:8080/api/test")

    # Verify URL was modified by the interceptor before being passed to original request:
    # 1. Host/port from config
    # 2. /dataservice prefix added
    assert len(captured_urls) == 1
    assert "example.myworkday.com:443" in captured_urls[0]
    assert "/dataservice/api/test" in captured_urls[0]


@patch('workday_ldq.auth_jwt_bearer_grant.jwt.encode')
def test_url_modification_always_applies_gateway_prefix(mock_jwt_encode):
    """Test that /dataservice prefix is always applied (includePathPrefix removed)"""

    props = {
        DriverProperty.TOKEN_ENDPOINT: "https://example.com/token",
        DriverProperty.CLIENT_ID: "client123",
        DriverProperty.ISU: "testuser",
        DriverProperty.PRIVATE_KEY: "fake-key-for-testing",
        DriverProperty.HOST: "example.myworkday.com",
    }
    config = LDQConfig(props)

    # Create a valid JWT token
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({"tenant": "test_tenant"}).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip('=')
    mock_jwt_token = f"{header}.{payload}.{signature}"

    mock_jwt_encode.return_value = "mocked_jwt"
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        TokenParam.ACCESS_TOKEN: mock_jwt_token,
        TokenParam.EXPIRES_IN: 3600
    }

    auth = JwtBearerAuth(config)
    auth._http_session.post = Mock(return_value=mock_response)

    # Track URLs passed to the ORIGINAL request function (after interception)
    captured_urls = []

    def mock_request_func(method, url, **kwargs):
        captured_urls.append(url)
        response = Mock()
        response.status_code = 200
        return response

    mock_session = Mock()
    mock_session.headers = {}
    mock_session.request = mock_request_func

    # This wraps mock_request_func with the interceptor
    auth.set_http_session(mock_session)

    # Make a request - mock_session.request is now the interceptor
    mock_session.request("GET", "http://original-host:8080/api/test")

    # Verify URL was modified by the interceptor:
    # 1. Host/port from config
    # 2. /dataservice prefix always applied
    assert len(captured_urls) == 1
    assert "example.myworkday.com:443" in captured_urls[0]
    assert "/dataservice" in captured_urls[0]
    assert "/api/test" in captured_urls[0]
