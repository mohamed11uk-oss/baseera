PY ?= .venv/bin/python
.PHONY: install dev test lint eval check openapi screenshots pptx

install:
	test -x .venv/bin/python || python3 -m venv .venv
	.venv/bin/pip install -q -r requirements.txt

dev: install
	$(PY) -m baseera serve

test:
	BASEERA_MODE=offline $(PY) -m pytest -q

lint:
	$(PY) -m ruff check baseera tests scripts

eval:
	BASEERA_MODE=offline $(PY) scripts/calibrate.py

check:
	./scripts/check.sh

openapi:
	BASEERA_MODE=offline $(PY) -m baseera export-openapi > docs/openapi.json

screenshots:
	$(PY) scripts/screenshots.py

pptx:
	$(PY) scripts/make_pptx.py
