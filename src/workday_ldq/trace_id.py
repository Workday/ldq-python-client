# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Trace ID tracking for Workday Live Data Query (LDQ) queries.

A single trace ID is kept for every HTTP request of one Trino query execution: the initial
``POST /v1/statement``, each ``GET`` on ``nextUri``.
The ID is sent in the Trino trace token header ``x-trino-trace-token`` and in ``x-wd-request-id``.

Only ``/v1/statement`` calls are tracked; any other request passes through untouched.

Only a successful ``POST`` response is inspected, to learn the real query ID and re-key the entry
under it. If that fails (non-2xx, unparsable body, or a transport error) the temporary key is left
in place and later polls of that query carry no trace header. ``GET``/``DELETE`` requests only look
up the trace ID and never modify the map; every entry is reclaimed by the idle TTL and size bound.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from collections import OrderedDict
from typing import Optional, Tuple

import requests

from .constants import (
    HTTP_METHOD_POST,
    TRACE_ID_IDLE_TTL_SECONDS,
    TRACE_ID_MAX_PEEK_BYTES,
    TRACE_ID_MAX_TRACKED_QUERIES,
    TRACE_ID_PREFIX,
)

logger = logging.getLogger(__name__)

STATEMENT_URI_PATH = "/v1/statement"

# Query ID in /v1/statement/queued/20260304_182502_00107_2xgc8/...
_IN_PROGRESS_QUERY_PATTERN = re.compile(r"/v1/statement/(?:queued|executing)/([^/]+)")
# "id":"20260304_182502_00107_2xgc8" in the POST response
_JSON_QUERY_ID_PATTERN = re.compile(r'"id"\s*:\s*"(\d{8}_\d{6}_\d{5}_[a-z0-9]+)"')


class TraceContext:
    """Trace state of a single statement request.

    ``trace_id`` is None for a poll/cancel whose query is not tracked (unknown or evicted); such a
    request is sent without trace headers. Only a new query (POST) is completed from its response.
    """

    def __init__(self, tracker: "TraceIdTracker", key: str, trace_id: Optional[str], is_new_query: bool) -> None:
        self._tracker = tracker
        self._key = key
        self.trace_id = trace_id
        self._is_new_query = is_new_query

    def on_response(self, response: requests.Response) -> None:
        """For a successful POST, re-key the query under its real ID. Anything else leaves the map alone."""
        if not (self._is_new_query and response.ok):
            return

        head = _peek_response_head(response)
        id_match = _JSON_QUERY_ID_PATTERN.search(head) if head else None
        if id_match is None:
            logger.warning("Could not find query ID in POST response; ending trace %s", self.trace_id)
            return

        real_id = id_match.group(1)
        self._tracker._rekey(self._key, real_id, self.trace_id)
        logger.info("TraceId='%s' for queryid='%s'", self.trace_id, real_id)


class TraceIdTracker:
    """Maps in-flight Trino query IDs to trace IDs. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> (trace_id, last_access_monotonic); ordered by recency of access
        self._entries: OrderedDict[str, Tuple[str, float]] = OrderedDict()
        self._request_counter = 0

    def track(self, method: str, url: str) -> Optional[TraceContext]:
        """Return the trace context for a request, or None if the request is not a statement call."""
        path = requests.utils.urlparse(url).path
        if STATEMENT_URI_PATH not in path:
            return None

        is_new_query = method.upper() == HTTP_METHOD_POST and path.endswith(STATEMENT_URI_PATH)

        with self._lock:
            if is_new_query:
                self._request_counter += 1
                key = f"POST_{self._request_counter}"
                trace_id = self._create(key)
            else:
                # Look-up only: never creates or removes an entry.
                match = _IN_PROGRESS_QUERY_PATTERN.search(path)
                key = match.group(1) if match else ""
                trace_id = self._lookup(key) if match else None
        return TraceContext(self, key, trace_id, is_new_query)

    @staticmethod
    def new_trace_id() -> str:
        """Create a standalone trace ID for a request that is not part of a tracked query."""
        return f"{TRACE_ID_PREFIX}{uuid.uuid4()}"

    def tracked_query_count(self) -> int:
        with self._lock:
            self._evict_expired()
            return len(self._entries)

    # -- internals (callers outside ``track`` take the lock here) --

    def _create(self, key: str) -> str:
        self._evict_expired()
        trace_id = self.new_trace_id()
        self._entries[key] = (trace_id, time.monotonic())
        self._entries.move_to_end(key)
        while len(self._entries) > TRACE_ID_MAX_TRACKED_QUERIES:
            # A size eviction can drop a live query's trace ID, so make it visible.
            evicted_key, (evicted_trace_id, _) = self._entries.popitem(last=False)
            logger.debug("Trace entry evicted (size): key=%s, traceId=%s", evicted_key, evicted_trace_id)
        return trace_id

    def _lookup(self, key: str) -> Optional[str]:
        """Return the trace ID of a tracked query (refreshing its idle timer), or None."""
        self._evict_expired()
        entry = self._entries.get(key)
        if entry is None:
            return None
        self._entries[key] = (entry[0], time.monotonic())
        self._entries.move_to_end(key)
        return entry[0]

    def _evict_expired(self) -> None:
        cutoff = time.monotonic() - TRACE_ID_IDLE_TTL_SECONDS
        while self._entries:
            oldest_key, (_, last_access) = next(iter(self._entries.items()))
            if last_access >= cutoff:
                break
            del self._entries[oldest_key]
            logger.debug("Trace entry evicted (expired): key=%s", oldest_key)

    def _rekey(self, old_key: str, new_key: str, trace_id: str) -> None:
        with self._lock:
            self._entries.pop(old_key, None)
            self._entries[new_key] = (trace_id, time.monotonic())
            self._entries.move_to_end(new_key)


def _peek_response_head(response: requests.Response) -> Optional[str]:
    """Return the first bytes of a statement response as text, or None if unreadable.

    Trino serialises QueryResults as id, infoUri, partialCancelUri, nextUri, columns, data, ..., so
    both ``id`` and ``nextUri`` sit within the first few hundred bytes. requests has already
    decoded any gzip body, so no decompression is needed here. Only used for the POST response.
    """
    try:
        return response.content[:TRACE_ID_MAX_PEEK_BYTES].decode("utf-8", errors="ignore")
    except Exception as e:
        logger.warning("Failed to read response head: %s", e)
        return None
