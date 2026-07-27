# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

# API documentation

HTML API reference for the Workday Live Data Query (LDQ) Python client
(analogous to Javadoc from `./gradlew javadoc` in `ldq-jdbc-driver`).

Generated output under `docs/api/` is local only — same as JDBC
`build/docs/javadoc/` — and is gitignored. Do not commit it.

## Generate locally

From the repository root (Python 3.9+):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[docs]"
./scripts/generate-api-docs.sh
```

Open `docs/api/index.html` in a browser.

Partner entry points: `create_connection`, `__version__`. Supporting modules are
included for reference.
