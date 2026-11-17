.PHONY: setup test validate fixtures integration targets-up targets-reset targets-down
PYTHON ?= python3
COMPOSE ?= docker compose
TARGETS_COMPOSE ?= targets/docker-compose.yml

setup:
	$(PYTHON) -m pip install '.[dev,app]'

test:
	$(PYTHON) -m pytest -q

validate:
	$(PYTHON) -m sable.cli validate snapshot tests/fixtures/snapshots/weak1.json
	$(PYTHON) -m sable.cli validate results tests/fixtures/results/weak1.json --snapshot tests/fixtures/snapshots/weak1.json

fixtures:
	$(PYTHON) tests/fixtures/regenerate.py

# Offline target acceptance (no Docker): analyse each target snapshot and compare
# against its expected.yaml.
integration:
	$(PYTHON) -m pytest -q tests/integration

# TE-04: build and run the four Docker lab targets (needs Docker).
targets-up:
	$(COMPOSE) -f $(TARGETS_COMPOSE) up -d --build

targets-reset:
	$(COMPOSE) -f $(TARGETS_COMPOSE) down -v
	$(COMPOSE) -f $(TARGETS_COMPOSE) up -d --build --force-recreate

targets-down:
	$(COMPOSE) -f $(TARGETS_COMPOSE) down -v
