.PHONY: install lint test test-integration lab-up lab-down attack e2e

PYTHON ?= python3
PYTEST ?= pytest
RUFF ?= ruff

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(RUFF) check sentinelx tests

test:
	$(PYTEST) -m "not integration"

test-integration:
	$(PYTEST) -m integration

lab-up:
	bash lab/netns_up.sh

lab-down:
	bash lab/netns_down.sh

attack:
	bash lab/attack.sh

e2e:
	bash lab/e2e.sh
