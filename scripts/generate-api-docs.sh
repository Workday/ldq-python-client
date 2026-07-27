#!/usr/bin/env bash
# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
#
# Generate HTML API docs for workday_ldq (Javadoc-style).
# Analogous to: ./gradlew javadoc  (ldq-jdbc-driver)
#
# Output: docs/api/  (gitignored — do not commit)
# Requires: package installed editable with pdoc, e.g. pip install -e ".[docs]"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT_DIR="${1:-docs/api}"

if ! command -v pdoc >/dev/null 2>&1; then
  echo "error: pdoc not found. Install with: pip install -e \".[docs]\"" >&2
  exit 1
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

pdoc \
  workday_ldq \
  workday_ldq.connector \
  workday_ldq.config \
  workday_ldq.driver_property \
  workday_ldq.auth_model \
  workday_ldq.auth_jwt_bearer_grant \
  workday_ldq.auth_code_grant \
  workday_ldq.auth_code_pkce_grant \
  workday_ldq.base_auth \
  workday_ldq.constants \
  workday_ldq.callback_server \
  -o "${OUT_DIR}"

test -f "${OUT_DIR}/index.html"

echo "API docs written to ${OUT_DIR}/ (open ${OUT_DIR}/index.html)"
