# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ldq-python-client")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
