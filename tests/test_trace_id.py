# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Tests for trace ID propagation"""

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
import requests

from workday_ldq import trace_id as trace_module
from workday_ldq.auth_jwt_bearer_grant import JwtBearerAuth
from workday_ldq.base_auth import CachedToken
from workday_ldq.config import LDQConfig
from workday_ldq.constants import HTTP_HEADERS, HTTPHeader
from workday_ldq.driver_property import DriverProperty
from workday_ldq.trace_id import TraceIdTracker

QUERY_ID = "20260304_182502_00107_2xgc8"
BASE = "https://wd.example.com:443"
STATEMENT = f"{BASE}/v1/statement"
EXECUTING = f"{BASE}/v1/statement/executing/{QUERY_ID}/abc/1"


def _response(body: str, status: int = 200) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp._content = body.encode()
    return resp


def _with_next(query_id=QUERY_ID):
    return _response(f'{{"id":"{query_id}","nextUri":"{EXECUTING}","columns":[]}}')


def _last_page(query_id=QUERY_ID):
    return _response(f'{{"id":"{query_id}","columns":[],"data":[[1]]}}')


def _props(**extra):
    props = {
        DriverProperty.AUTH_MODEL: "JWT_BEARER",
        DriverProperty.TOKEN_ENDPOINT: "https://example.com/token",
        DriverProperty.CLIENT_ID: "c",
        DriverProperty.ISU: "isu",
        DriverProperty.PRIVATE_KEY: "k",
        DriverProperty.HOST: "wd.example.com",
    }
    props.update(extra)
    return props


class TestTracker:
    def test_non_statement_requests_are_untouched(self):
        t = TraceIdTracker()
        assert t.track("GET", f"{BASE}/v1/info") is None
        assert t.track("GET", f"{BASE}/v1/stage/xyz") is None
        assert t.tracked_query_count() == 0

    def test_trace_id_has_ldq_prefix(self):
        post = TraceIdTracker().track("POST", STATEMENT)
        assert post.trace_id.startswith("LDQ|")

    def test_same_trace_id_across_query_lifecycle(self):
        t = TraceIdTracker()
        post = t.track("POST", STATEMENT)
        post.on_response(_with_next())
        poll1 = t.track("GET", EXECUTING)
        poll1.on_response(_with_next())
        poll2 = t.track("GET", EXECUTING)
        assert post.trace_id == poll1.trace_id == poll2.trace_id
        assert t.tracked_query_count() == 1

    def test_last_page_does_not_end_tracking(self):
        t = TraceIdTracker()
        post = t.track("POST", STATEMENT)
        post.on_response(_with_next())
        poll = t.track("GET", EXECUTING)
        poll.on_response(_last_page())
        assert t.tracked_query_count() == 1
        assert t.track("GET", EXECUTING).trace_id == post.trace_id

    def test_error_response_keeps_trace_id(self):
        t = TraceIdTracker()
        t.track("POST", STATEMENT).on_response(_with_next())
        first = t.track("GET", EXECUTING)
        first.on_response(_response("", status=503))
        assert t.track("GET", EXECUTING).trace_id == first.trace_id

    def test_delete_does_not_end_tracking(self):
        t = TraceIdTracker()
        t.track("POST", STATEMENT).on_response(_with_next())
        t.track("DELETE", EXECUTING).on_response(_response("", status=204))
        assert t.tracked_query_count() == 1

    def test_poll_of_unknown_query_is_untracked_and_not_recorded(self):
        t = TraceIdTracker()
        ctx = t.track("GET", EXECUTING)
        ctx.on_response(_with_next())
        assert ctx.trace_id is None
        assert t.tracked_query_count() == 0

    def test_post_with_unrecoverable_id_leaves_polls_untraced(self):
        t = TraceIdTracker()
        t.track("POST", STATEMENT).on_response(_response('{"nextUri":"x"}'))
        assert t.track("GET", EXECUTING).trace_id is None
        # the temporary key stays until the idle TTL / size bound reclaims it
        assert t.tracked_query_count() == 1

    def test_successful_post_is_filed_under_real_id_only(self):
        t = TraceIdTracker()
        t.track("POST", STATEMENT).on_response(_with_next())
        assert t.tracked_query_count() == 1
        assert t.track("GET", f"{BASE}/v1/statement/executing/other_query/1").trace_id is None

    def test_failed_post_leaves_map_untouched(self):
        t = TraceIdTracker()
        t.track("POST", STATEMENT).on_response(_response("", status=500))
        assert t.tracked_query_count() == 1

    def test_concurrent_queries_get_distinct_ids(self):
        t = TraceIdTracker()
        a, b = t.track("POST", STATEMENT), t.track("POST", STATEMENT)
        a.on_response(_with_next("20260304_182502_00107_aaaaa"))
        b.on_response(_with_next("20260304_182502_00108_bbbbb"))
        assert a.trace_id != b.trace_id
        assert t.tracked_query_count() == 2

    def test_idle_entries_expire(self, monkeypatch):
        t = TraceIdTracker()
        t.track("POST", STATEMENT).on_response(_with_next())
        monkeypatch.setattr(time, "monotonic", lambda: time.time() + trace_module.TRACE_ID_IDLE_TTL_SECONDS + 5)
        assert t.tracked_query_count() == 0

    def test_size_is_capped(self, monkeypatch):
        monkeypatch.setattr(trace_module, "TRACE_ID_MAX_TRACKED_QUERIES", 3)
        t = TraceIdTracker()
        for _ in range(10):
            t.track("POST", STATEMENT)
        assert t.tracked_query_count() == 3


class TestConfig:
    @pytest.mark.parametrize("value,expected", [
        (None, True), ("true", True), ("", True), ("flase", True),
        ("false", False), (" FALSE ", False),
    ])
    def test_trace_id_enabled(self, value, expected):
        extra = {} if value is None else {DriverProperty.TRACE_ID_ENABLED: value}
        assert LDQConfig(_props(**extra)).trace_id_enabled is expected


class TestInterceptor:
    def _auth_and_session(self, **extra):
        auth = JwtBearerAuth(LDQConfig(_props(**extra)))
        auth._cached_token_data = CachedToken(
            access_token="tok", expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        session = Mock()
        session.headers = {}
        original = Mock(side_effect=lambda m, u, **kw: _with_next())
        session.request = original
        auth._set_auth_headers = Mock()
        auth.set_http_session(session)
        return auth, session, original

    def test_statement_requests_carry_trace_headers(self):
        _, session, original = self._auth_and_session()
        session.request("POST", STATEMENT)
        session.request("GET", EXECUTING, headers={"X-Other": "1"})
        first = original.call_args_list[0].kwargs[HTTP_HEADERS]
        second = original.call_args_list[1].kwargs[HTTP_HEADERS]
        assert first[HTTPHeader.TRINO_TRACE_TOKEN] == first[HTTPHeader.WD_REQUEST_ID]
        assert second[HTTPHeader.TRINO_TRACE_TOKEN] == first[HTTPHeader.TRINO_TRACE_TOKEN]
        assert second["X-Other"] == "1"

    def test_other_requests_have_no_trace_headers(self):
        _, session, original = self._auth_and_session()
        session.request("GET", f"{BASE}/v1/info")
        assert HTTP_HEADERS not in original.call_args.kwargs

    def test_disabled_adds_no_headers(self):
        _, session, original = self._auth_and_session(**{DriverProperty.TRACE_ID_ENABLED: "false"})
        session.request("POST", STATEMENT)
        assert HTTP_HEADERS not in original.call_args.kwargs

    def test_token_refresh_on_401_carries_query_trace_id(self):
        auth, session, original = self._auth_and_session()
        original.side_effect = [_response("", status=401), _with_next()]
        auth.get_token = Mock(return_value="new")
        session.request("POST", STATEMENT)
        sent = original.call_args_list[0].kwargs[HTTP_HEADERS][HTTPHeader.TRINO_TRACE_TOKEN]
        auth.get_token.assert_called_once_with(sent)


class TestTokenRequests:
    def test_token_request_carries_request_id(self):
        auth = JwtBearerAuth(LDQConfig(_props()))
        auth._http_session = Mock()
        auth._http_session.post.return_value = _response('{"access_token":"a","expires_in":60}')
        with patch("workday_ldq.auth_jwt_bearer_grant.jwt.encode", return_value="assertion"):
            auth.get_new_access_token("trace-123")
        assert auth._http_session.post.call_args.kwargs[HTTP_HEADERS][HTTPHeader.WD_REQUEST_ID] == "trace-123"

    def test_token_request_without_trace_id_has_no_request_id(self):
        auth = JwtBearerAuth(LDQConfig(_props()))
        auth._http_session = Mock()
        auth._http_session.post.return_value = _response('{"access_token":"a","expires_in":60}')
        with patch("workday_ldq.auth_jwt_bearer_grant.jwt.encode", return_value="assertion"):
            auth.get_new_access_token()
        assert HTTPHeader.WD_REQUEST_ID not in auth._http_session.post.call_args.kwargs[HTTP_HEADERS]
