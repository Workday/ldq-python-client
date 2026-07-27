# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Main connector module for Workday Live Data Query (LDQ)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Union

import trino

from ._version import __version__
from .config import LDQConfig

CreateConnectionArg = Union[LDQConfig, Dict[str, str], str, Path]


def create_connection(config: CreateConnectionArg):
    """Create a Workday Live Data Query (LDQ) connection.

    The authentication flow is selected via ``wd.authn.authModel``
    (``JWT_BEARER``, ``AUTHORIZATION_CODE``, or ``AUTHORIZATION_CODE_PKCE``).

    Args:
        config: Connection settings as one of:

            - an :class:`~workday_ldq.config.LDQConfig` instance
            - a ``dict`` of property keys to values (same keys as a ``.properties`` file)
            - a path (``str`` or :class:`~pathlib.Path`) to a Java-style ``.properties`` file

    Returns:
        A Trino DB-API connection (``trino.dbapi.Connection``) ready for
        ``cursor()`` / ``execute()`` / ``fetchall()``.

    Example:
        >>> from workday_ldq import create_connection
        >>> conn = create_connection("ldq.properties")
        >>> cursor = conn.cursor()
        >>> cursor.execute("SELECT * FROM worker LIMIT 10")
    """
    effective_config: LDQConfig
    if isinstance(config, LDQConfig):
        effective_config = config
    elif isinstance(config, dict):
        effective_config = LDQConfig(config)
    else:
        effective_config = LDQConfig.from_file(str(config))

    auth = effective_config.create_authentication()

    connection_kwargs = {
        "host": effective_config.host,
        "port": effective_config.port,
        "catalog": effective_config.catalog,
        "schema": effective_config.schema,
        "http_scheme": "https",
        "auth": auth,
        "source": f"ldq-python-client:{__version__}",
    }

    if effective_config.http_timeout:
        connection_kwargs["request_timeout"] = effective_config.http_timeout

    if effective_config.session_properties:
        connection_kwargs["session_properties"] = effective_config.session_properties

    return trino.dbapi.connect(**connection_kwargs)
