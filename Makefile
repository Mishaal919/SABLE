.PHONY: setup test validate fixtures
PYTHON ?= python3

setup:
	$(PYTHON) -m pip install '.[dev,app]'

test:
	$(PYTHON) -m pytest -q

validate:
	$(PYTHON) -m sable.cli validate snapshot tests/fixtures/snapshots/weak1.json
	$(PYTHON) -m sable.cli validate results tests/fixtures/results/weak1.json --snapshot tests/fixtures/snapshots/weak1.json

fixtures:
	$(PYTHON) tests/fixtures/regenerate.py
