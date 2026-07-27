# Workday Live Data Query (LDQ) Python Client

Python connector for Workday Live Data Query (LDQ). PyPI package: **`ldq-python-client`**; import as **`workday_ldq`**.

Dependencies install from **PyPI**. See [Requirements](#requirements) and [Installation](#installation) below.

## Requirements

- Python 3.9+

## Installation

### From a wheel

```bash
pip install ldq_python_client-*.whl
```

### From source (editable)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Prerequisites

Register an API client in Workday to obtain OAuth credentials. The registration UI differs by grant type:

- **JWT Bearer Grant** — you will obtain: `clientId`, ISU username, private key, and the **Token Endpoint URL**
- **Authorization Code Grant** — you will obtain: `clientId`, `clientSecret`, redirect URL, **Token Endpoint URL**, and **Authorization Endpoint URL**

OAuth endpoint URLs are shown on the API client registration page after registration. Use them in `ldq.properties` as below.

## Quick Start

### 1. Configuration (`ldq.properties`)

Auth model via `wd.authn.authModel` (case-insensitive): `JWT_BEARER` (default) or `AUTHORIZATION_CODE`.

#### `JWT_BEARER`

```properties
wd.authn.authModel=JWT_BEARER
wd.authn.accessTokenEndpoint=https://YOUR_TENANT.myworkday.com/ccx/oauth2/YOUR_TENANT/token
wd.authn.clientId=YOUR_CLIENT_ID
wd.authn.isu=YOUR_ISU_USERNAME
wd.authn.privateKeyFile=/path/to/private-key.pem
wd.host=YOUR_TENANT.myworkday.com
```

Or set `wd.authn.privateKey` inline instead of `wd.authn.privateKeyFile`.

#### `AUTHORIZATION_CODE`

```properties
wd.authn.authModel=AUTHORIZATION_CODE
wd.authn.accessTokenEndpoint=https://YOUR_TENANT.myworkday.com/ccx/oauth2/YOUR_TENANT/token
wd.authn.clientId=YOUR_CLIENT_ID
wd.authn.authorizationEndpoint=https://YOUR_TENANT.myworkday.com/ccx/oauth2/YOUR_TENANT/authorize
wd.authn.redirectUrl=https://localhost:8888/callback
wd.authn.clientSecret=YOUR_CLIENT_SECRET
wd.host=YOUR_TENANT.myworkday.com
```

### 2. Connect and query

```python
from workday_ldq import create_connection

conn = create_connection("ldq.properties")
cursor = conn.cursor()
cursor.execute("SELECT * FROM worker LIMIT 10")
results = cursor.fetchall()
cursor.close()
conn.close()
```

## Configuration reference

| Property | Default | Description |
|----------|---------|-------------|
| `wd.host` | `localhost` | Workday / LDQ host |
| `wd.port` | `443` | Port |
| `wd.catalog` | `workday_core` | Catalog |
| `wd.schema` | `public` | Schema |
| `wd.http.timeout` | `30` | HTTP request timeout in seconds |
| `wd.sessionProperties` | (none) | Trino session properties (comma-separated `key=value` pairs, e.g. `query_max_run_time=2h,exchange_order=ANY`) |

### Deprecated properties

The following property has been removed and is no longer supported:

- `wd.authn.includePathPrefix`

## Development

Install dev dependencies (editable):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run all unit tests

Integration tests are marked with `@pytest.mark.integration` and require a live environment. Skip them for local/offline development:

```bash
pytest -m "not integration"
```

### Run a single test module

```bash
pytest tests/test_auth.py
pytest tests/test_connector.py
```

### Run a single test function

```bash
pytest tests/test_auth.py::test_token_caching
pytest tests/test_connector.py::test_create_connection
```

### Run tests matching a name pattern

```bash
pytest -k "thread_safety"
```

### Integration tests (live environment)

Requires a configured tenant and browser login for authorization-code flows:

```bash
pytest -m integration
```

### Build wheel / sdist

```bash
pip install build
python -m build
```

Artifacts land under `dist/`.

## API documentation

Generate HTML API reference locally (same role as `./gradlew javadoc` in `ldq-jdbc-driver`).
Output under `docs/api/` is not committed (like `build/docs/javadoc/`). CI runs this on every build.

```bash
pip install -e ".[docs]"   # or .[dev], which includes pdoc
./scripts/generate-api-docs.sh
```

Open `docs/api/index.html` in a browser. Partner entry points: `create_connection`, `__version__`.
See [`docs/README.md`](docs/README.md) for details.

## Troubleshooting

### Authorization Code Grant timeout

Browser login must complete within **3 minutes**. Check redirect URL match, firewall on the callback port, and retry.

## License

Apache-2.0 — see [LICENSE](LICENSE), [NOTICE](NOTICE), and [CONTRIBUTING](CONTRIBUTING.md).
