# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Shared HTTP client configuration for OAuth operations.

This module provides a factory function for creating configured requests.Session
instances for OAuth token requests. This ensures efficient connection reuse across
all OAuth token requests

    Session provides connection pooling, automatic retries

    Retry Strategy:
      - Retries on HTTP 429 (Too Many Requests) and 5xx (Server Errors)
      - Exponential backoff: delay = backoff_factor * (2 ** (retry_count - 1))
      - Random jitter applied to prevent thundering herd (configurable)
      - Maximum delay capped in seconds (configurable, see ConnectionRetry.MAX_DELAY_SEC)
      - Only retries POST requests (for OAuth token operations)

    Connection Pool:
      - Maintains pool of persistent connections (default: 10)
      - Reuses connections to same host
      - Automatically handles HTTP/1.1 keep-alive

    Configuration (via environment variables)
"""

import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .constants import (
    ConnectionRetry,
    RETRY_STATUS_CODES,
    DEFAULT_POOL_CONNECTIONS,
    DEFAULT_POOL_MAXSIZE,
    HTTPS_SCHEME,
    HTTP_SCHEME,
    HTTP_METHOD_POST,
)


def _resolve_use_jitter() -> bool:
    return ConnectionRetry.BACKOFF_JITTER.resolve().lower() in ("true", "1", "yes")


class _RetryWithJitter(Retry):

    def __init__(self, *args, total: int = None, backoff_factor: float = None,
                 max_backoff: int = None, use_jitter: bool = None, **kwargs):
        total = total if total is not None else int(ConnectionRetry.MAX_RETRIES.resolve())
        backoff_factor = backoff_factor if backoff_factor is not None else float(ConnectionRetry.BACKOFF_MULTIPLIER.resolve())
        super().__init__(*args, total=total, backoff_factor=backoff_factor, **kwargs)
        self._max_backoff = max_backoff if max_backoff is not None else int(ConnectionRetry.MAX_DELAY_SEC.resolve())
        self._use_jitter = use_jitter if use_jitter is not None else _resolve_use_jitter()

    def new(self, **kw):
        kw.setdefault("max_backoff", self._max_backoff)
        kw.setdefault("use_jitter", self._use_jitter)
        return super().new(**kw)

    def get_backoff_time(self) -> float:

        backoff = super().get_backoff_time()

        if self._use_jitter:
            backoff *= random.random()

        if self._max_backoff is not None:
            backoff = min(backoff, self._max_backoff)

        return backoff


def create_oauth_http_session() -> requests.Session:

    session = requests.Session()

    retry_strategy = _RetryWithJitter(
        status_forcelist=RETRY_STATUS_CODES,
        allowed_methods=[HTTP_METHOD_POST],   # Only retry POST for OAuth token requests
        raise_on_status=False,      # Don't raise exception on retries
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=DEFAULT_POOL_CONNECTIONS,
        pool_maxsize=DEFAULT_POOL_MAXSIZE,
    )

    session.mount(HTTPS_SCHEME, adapter)
    session.mount(HTTP_SCHEME, adapter)

    return session
