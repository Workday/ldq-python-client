# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Workday Live Data Query (LDQ) Python client — supported public API."""

from .connector import create_connection

from ._version import __version__

__all__ = [
    "create_connection",
    "__version__",
]
