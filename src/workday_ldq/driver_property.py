# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Enum of all Workday Live Data Query (LDQ) driver property keys."""

from enum import Enum


class DriverProperty(str, Enum):
    """All recognised driver property keys.

    Being a str Enum, each member is interchangeable with its string value
    wherever a property key is expected (dict lookups, cfg.get(), etc.).
    """

    AUTH_MODEL = "wd.authn.authModel"
    TOKEN_ENDPOINT = "wd.authn.accessTokenEndpoint"
    CLIENT_ID = "wd.authn.clientId"
    ISU = "wd.authn.isu"
    PRIVATE_KEY = "wd.authn.privateKey"
    PRIVATE_KEY_FILE = "wd.authn.privateKeyFile"
    AUTHORIZATION_ENDPOINT = "wd.authn.authorizationEndpoint"
    REDIRECT_URL = "wd.authn.redirectUrl"
    CLIENT_SECRET = "wd.authn.clientSecret"
    HOST = "wd.host"
    PORT = "wd.port"
    HTTP_REQUEST_TIMEOUT = "wd.http.timeout"
    CATALOG = "wd.catalog"
    SCHEMA = "wd.schema"
    SESSION_PROPERTIES = "wd.sessionProperties"
