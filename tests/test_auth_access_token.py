# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for ACCESS_TOKEN authentication"""

import time
from unittest.mock import Mock

import jwt
import pytest
from trino.constants import HEADER_EXTRA_CREDENTIAL

from workday_ldq.auth_access_token import AccessTokenAuth
from workday_ldq.auth_model import ACCESS_TOKEN
from workday_ldq.config import LDQConfig
from workday_ldq.constants import HTTPHeader
from workday_ldq.driver_property import DriverProperty


def _jwt(**claims) -> str:
    return jwt.encode(claims, "test-secret-key-at-least-32-bytes-long", algorithm="HS256")


def _props(token=None, **overrides):
    props = {
        DriverProperty.AUTH_MODEL: "ACCESS_TOKEN",
        DriverProperty.ACCESS_TOKEN: token or _jwt(tenant="acme", exp=int(time.time()) + 3600),
        DriverProperty.HOST: "example.myworkday.com",
    }
    props.update(overrides)
    return props


def _session():
    session = Mock()
    session.headers = {}
    return session

class TestValidation:
    def test_valid_config(self):
        cfg = LDQConfig(_props())
        assert cfg.auth_model == ACCESS_TOKEN
        assert isinstance(cfg.create_authentication(), AccessTokenAuth)

    def test_missing_token_raises(self):
        props = _props()
        del props[DriverProperty.ACCESS_TOKEN]
        with pytest.raises(ValueError, match="Missing required properties for ACCESS_TOKEN"):
            LDQConfig(props)


class TestHeaders:
    def test_bearer_headers_with_tenant_from_claim(self):
        cfg = LDQConfig(_props())
        session = _session()
        AccessTokenAuth(cfg).set_http_session(session)

        token = cfg.access_token
        assert session.headers[HTTPHeader.AUTHORIZATION] == f"Bearer {token}"
        assert session.headers[HTTPHeader.TENANT] == "acme"
        assert session.headers[HEADER_EXTRA_CREDENTIAL] == f"token={token}"

    def test_missing_tenant_claim_raises(self):
        cfg = LDQConfig(_props(_jwt(sub="user", exp=int(time.time()) + 3600)))
        with pytest.raises(ValueError, match="Tenant claim is missing"):
            AccessTokenAuth(cfg).set_http_session(_session())


class TestTokenHandling:
    def test_token_returned_as_supplied_and_cached(self):
        cfg = LDQConfig(_props())
        auth = AccessTokenAuth(cfg)
        assert auth.get_token() == cfg.access_token
        assert auth._is_token_valid()

    def test_token_without_exp_raises(self):
        auth = AccessTokenAuth(LDQConfig(_props(_jwt(tenant="acme"))))
        with pytest.raises(ValueError, match="missing an expiration"):
            auth.get_token()

    def test_non_jwt_token_raises(self):
        auth = AccessTokenAuth(LDQConfig(_props("not-a-jwt")))
        with pytest.raises(ValueError, match="Failed to parse supplied access token as a JWT"):
            auth.get_token()

    def test_expired_token_is_not_valid_and_not_refreshed(self):
        token = _jwt(tenant="acme", exp=int(time.time()) - 10)
        auth = AccessTokenAuth(LDQConfig(_props(token)))
        assert auth.get_token() == token
        assert not auth._is_token_valid()
        assert auth.try_refresh_token_grant() is None

    def test_retries_once_on_401_like_other_models(self):
        auth = AccessTokenAuth(LDQConfig(_props()))
        session = _session()
        response = Mock(status_code=401)
        original = Mock(return_value=response)
        session.request = original
        auth.set_http_session(session)

        result = session.request("GET", "https://example.com/v1/statement")

        assert result is response
        assert original.call_count == 2
