# Release Notes - LDQ Python Client

## Version 1.1.2

### Added
- Reusable HTTP sessions for OAuth token requests, with connection pooling and configurable retries for rate limits and transient server errors.

## Version 1.1.0

### Added
- HTTP (in addition to HTTPS) for the local OAuth authorization-code callback server.

### Fixed
- Dependency pins for known vulnerabilities (`requests>=2.33.0`, `orjson>=3.11.6`).

## Version 1.0.0

Initial open source release of the Workday Live Data Query Python client.

### Added
- `wd.http.timeout` — HTTP request timeout in seconds (default: `30`), passed to Trino as `request_timeout`.
- `wd.sessionProperties` — Trino session properties as comma-separated `key=value` pairs.

### Removed
- `wd.authn.includePathPrefix` — `/dataservice` path prefix is now always applied.
