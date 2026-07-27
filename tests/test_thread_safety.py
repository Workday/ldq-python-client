# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for thread safety of token refresh logic"""

import jwt as jwt_lib
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest.mock import Mock, patch

import pytest
import requests

from workday_ldq.auth_jwt_bearer_grant import JwtBearerAuth
from workday_ldq.auth_model import AuthModel, JWT_BEARER, AUTHORIZATION_CODE
from workday_ldq.base_auth import CachedToken
from workday_ldq.config import LDQConfig
from workday_ldq.driver_property import DriverProperty


@pytest.fixture
def mock_config():
    props = {
        DriverProperty.TOKEN_ENDPOINT:   "https://example.com/token",
        DriverProperty.CLIENT_ID:        "client123",
        DriverProperty.ISU:              "testuser",
        DriverProperty.PRIVATE_KEY:      "fake-key-for-testing",
        DriverProperty.HOST:             "example.myworkday.com",
    }
    return LDQConfig(props)


def test_concurrent_token_refresh_only_calls_once(mock_config):
    """Test that concurrent get_token() calls only trigger one refresh."""
    auth = JwtBearerAuth(mock_config)

    # Make token appear expired
    auth._cached_token_data = CachedToken(access_token="old_token",
                                          expires_at=datetime.now(timezone.utc) - timedelta(seconds=10))

    refresh_count = {"count": 0}
    refresh_lock = threading.Lock()

    def mock_refresh(*args, **kwargs):
        """Mock refresh that tracks how many times it's called"""
        with refresh_lock:
            refresh_count["count"] += 1
        # Simulate slow refresh to increase chance of race condition
        time.sleep(0.1)
        # Actually cache the token properly
        auth._cached_token_data = CachedToken(access_token="new_token",
                                              expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        return "new_token"

    with patch.object(auth, 'get_new_access_token', side_effect=mock_refresh):
        # Launch 10 concurrent threads trying to get token
        threads = []
        results = []

        def get_token_wrapper():
            token = auth.get_token()
            results.append(token)

        for _ in range(10):
            t = threading.Thread(target=get_token_wrapper)
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

    # All threads should get the same token
    assert len(results) == 10
    assert all(token == "new_token" for token in results)

    # Critical assertion: refresh should only be called ONCE
    assert refresh_count["count"] == 1, \
        f"Expected 1 refresh call, but got {refresh_count['count']} (race condition!)"


def test_second_thread_waits_for_first_refresh(mock_config):
    """Test that second thread waits for first thread's refresh to complete."""
    auth: JwtBearerAuth = JwtBearerAuth(mock_config)

    # Make token appear expired
    auth._cached_token_data = CachedToken(access_token="old_token",
                                          expires_at=datetime.now(timezone.utc) - timedelta(seconds=10))

    refresh_started = threading.Event()
    refresh_can_complete = threading.Event()

    def slow_refresh(*args, **kwargs):
        """Mock refresh that blocks until we allow it to proceed"""
        refresh_started.set()
        refresh_can_complete.wait()  # Block here
        return "refreshed_token"

    with patch.object(auth, 'get_new_access_token', side_effect=slow_refresh):
        results = {"thread1": None, "thread2": None}

        def thread1_work():
            results["thread1"] = auth.get_token()

        def thread2_work():
            # Wait for thread1 to start refreshing
            refresh_started.wait()
            # Now try to get token - should wait for thread1 to finish
            results["thread2"] = auth.get_token()

        t1 = threading.Thread(target=thread1_work)
        t2 = threading.Thread(target=thread2_work)

        t1.start()
        t2.start()

        # Let refresh complete after both threads are waiting
        time.sleep(0.1)
        refresh_can_complete.set()

        t1.join()
        t2.join()

    # Both threads should get the same refreshed token
    assert results["thread1"] == "refreshed_token"
    assert results["thread2"] == "refreshed_token"


def test_fast_path_no_lock_contention(mock_config):
    """Test that valid tokens don't acquire lock (performance optimization)."""
    auth = JwtBearerAuth(mock_config)

    # Set a valid token
    auth._cached_token_data = CachedToken(access_token="valid_token",
                                          expires_at=datetime.now(timezone.utc) + timedelta(hours=1))

    # Multiple threads should be able to get token without blocking
    def get_token_multiple_times():
        for _ in range(100):
            token = auth.get_token()
            assert token == "valid_token"

    threads = [threading.Thread(target=get_token_multiple_times) for _ in range(10)]

    start_time = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start_time

    # Should complete quickly since no lock contention
    assert elapsed < 1.0, f"Took {elapsed}s - lock contention on fast path!"


def test_exception_chaining_preserves_traceback(mock_config):
    """Test that JWT parsing errors preserve the original exception via 'from e'."""
    auth = JwtBearerAuth(mock_config)

    # Create an invalid JWT (not properly base64 encoded)
    invalid_jwt = "not.a.valid.jwt"

    session = Mock()
    session.headers = {}

    try:
        auth._set_auth_headers(session, invalid_jwt)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        # Check that exception message is descriptive
        assert "Error parsing JWT access token" in str(e)

        # Check that original exception is preserved via __cause__
        assert e.__cause__ is not None, "Exception chain broken - use 'raise ... from e'"

        # Original exception should be a JWT decode error
        assert isinstance(e.__cause__, (jwt_lib.DecodeError, Exception))


def test_property_guards_raise_not_assert():
    """Test that property guards use 'if' + raise, not assert (which is stripped by -O)."""
    # Create config with minimal valid properties
    props = {
        DriverProperty.TOKEN_ENDPOINT:   "https://example.com/token",
        DriverProperty.CLIENT_ID:        "client123",
        DriverProperty.ISU:              "testuser",
        DriverProperty.PRIVATE_KEY:      "fake-key",
    }
    config = LDQConfig(props)

    # Manually break the internal state (simulates what happens with -O if using assert)
    config._properties.pop(DriverProperty.TOKEN_ENDPOINT)

    # Should raise RuntimeError, not return None
    try:
        _ = config.token_endpoint
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "TOKEN_ENDPOINT missing" in str(e)
        assert "should have been caught by _validate" in str(e)


def test_token_endpoint_error_includes_response_body(mock_config):
    """Test that token endpoint HTTP errors include the response body with error details."""
    auth = JwtBearerAuth(mock_config)

    # Mock a 400 error response with OAuth error details in body
    error_response = Mock()
    error_response.status_code = HTTPStatus.BAD_REQUEST
    error_response.text = '{"error": "invalid_grant", "error_description": "The refresh token has expired"}'
    error_response.raise_for_status.side_effect = requests.HTTPError("400 Client Error: Bad Request")

    auth._http_session.post = Mock(return_value=error_response)

    with patch('workday_ldq.auth_jwt_bearer_grant.jwt.encode', return_value='fake.jwt.token'):
        try:
            auth.get_new_access_token()
            assert False, "Should have raised HTTPError"
        except requests.HTTPError as e:
            error_msg = str(e)
            # Should include status code
            assert "400" in error_msg
            # Should include response body with error details
            assert "invalid_grant" in error_msg
            assert "refresh token has expired" in error_msg
            # Should preserve original exception via chain
            assert e.__cause__ is not None


def test_auth_model_enum():
    """Test that auth_model property returns AuthModel enum instead of string."""
    # JWT Bearer config
    jwt_props = {
        DriverProperty.TOKEN_ENDPOINT:   "https://example.com/token",
        DriverProperty.CLIENT_ID:        "client123",
        DriverProperty.ISU:              "testuser",
        DriverProperty.PRIVATE_KEY:      "fake-key",
    }
    jwt_config = LDQConfig(jwt_props)

    # Should return enum, not string
    assert isinstance(jwt_config.auth_model, AuthModel)
    assert jwt_config.auth_model == JWT_BEARER
    assert jwt_config.auth_model.value == "jwt_bearer"

    # Authorization Code config
    auth_code_props = {
        DriverProperty.AUTH_MODEL:              "AUTHORIZATION_CODE",
        DriverProperty.TOKEN_ENDPOINT:          "https://example.com/token",
        DriverProperty.AUTHORIZATION_ENDPOINT:  "https://example.com/authorize",
        DriverProperty.CLIENT_ID:               "client123",
        DriverProperty.CLIENT_SECRET:           "secret",
        DriverProperty.REDIRECT_URL:            "https://localhost:8888/callback",
    }
    auth_code_config = LDQConfig(auth_code_props)

    assert isinstance(auth_code_config.auth_model, AuthModel)
    assert auth_code_config.auth_model == AUTHORIZATION_CODE
    assert auth_code_config.auth_model.value == "authorization_code"
