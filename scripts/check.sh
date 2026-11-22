#!/usr/bin/env bash
# Same as `make check` for machines without make: ruff + pytest (offline).
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
$PY -m ruff check baseera tests scripts
BASEERA_MODE=offline $PY -m pytest -q
