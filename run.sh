#!/usr/bin/env bash
# One command: ./run.sh  -> creates .venv, installs deps, starts http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi
.venv/bin/pip install -q -r requirements.txt
exec .venv/bin/python -m baseera serve --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
