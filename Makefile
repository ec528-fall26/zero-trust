.PHONY: check test test-python test-node integration-nono demo demo-no-browser demo2-authorization demo2-attestation ci

PYTHON ?= python3

check:
	PYTHONPATH=src $(PYTHON) -m compileall -q src tests
	node --check src/controller/receipt_required_mcp.mjs
	node --check src/controller/keylime_mcp_client.mjs
	node --check src/keylime_mcp/attest_and_deploy.mjs
	node --check src/keylime_mcp/server.mjs

test-python:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

test-node:
	npm test

test: test-python test-node

integration-nono:
	PYTHONPATH=src $(PYTHON) experiments/nono_handoff_confinement.py --nono-binary "$(NONO_BINARY)"

demo:
	PYTHONPATH=src $(PYTHON) experiments/live_demo.py

demo-no-browser:
	PYTHONPATH=src $(PYTHON) experiments/live_demo.py --no-browser

demo2-authorization:
	./experiments/demo2_authorization.sh

demo2-attestation:
	./experiments/demo2_attestation.sh

ci: check test
