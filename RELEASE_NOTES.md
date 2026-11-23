# Release Notes - LDQ Python Client

## Version 1.3.0

### Added
- Trace ID per query: every HTTP request of a query (submit, poll, cancel) carries the same ID in the `X-Trino-Trace-Token` and `x-wd-request-id` headers. OAuth token requests triggered by a query send the same `x-wd-request-id`.
- `wd.traceId.enabled` — set to `false` to turn trace ID propagation off (default: `true`).

## Version 1.2.1

No public API changes.

## Version 1.2.0

### Added
- `ACCESS_TOKEN` auth model (`wd.authn.accessToken`) for using a pre-issued token directly, without a token exchange.

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
