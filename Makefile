.PHONY: check test test-python test-node integration-nono demo demo-no-browser demo2-authorization demo2-attestation ima-tamper jaeger trace-replay demo-record fetch-token ci

# Prefer the project virtualenv (it has jsonschema) and fall back to python3.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

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

# Needs the AWS stack and leaves its node in the failed state; tear down after.
ima-tamper:
	node experiments/ima_tamper.mjs

# Local trace viewer (loopback only). UI: http://127.0.0.1:16686
jaeger:
	docker rm -f ec528-jaeger >/dev/null 2>&1 || true
	docker run -d --name ec528-jaeger -p 127.0.0.1:16686:16686 -p 127.0.0.1:4318:4318 jaegertracing/all-in-one:1.62.0

STACK ?= ec528-zero-trust-demo

# Copy the deployed node's MCP token to build/aws-keylime/mcp-token (0600).
fetch-token:
	./infra/aws/fetch-token.sh $(STACK)

# Guided, paused run of every demo shot for screen recording (needs a deployed stack).
demo-record:
	./experiments/demo_record.sh $(STACK)

# Replay recorded results files as traces into the local Jaeger.
trace-replay:
	OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 node experiments/trace_replay.mjs

ci: check test
