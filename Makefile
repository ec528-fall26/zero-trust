.PHONY: check test test-python test-node integration-nono demo demo-no-browser demo2-authorization demo2-bootstrap demo2-attestation drift-policy drift-time drift-revocation drift-identity drift demo3-bridge demo3-bridge-aws demo3-human-approval demo3-human-approval-fixture demo3-trials demo3-trials-aws demo3-local demo3-model-agent demo3-claude-agent demo3-model-agent-replay demo3-summary ima-tamper jaeger trace-replay demo-record fetch-token ci

# Prefer the project virtualenv (it has jsonschema) and fall back to python3.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

check:
	PYTHONPATH=src $(PYTHON) -m compileall -q src tests
	bash -n experiments/*.sh infra/aws/*.sh infra/azure/*.sh infra/spire/*.sh
	node --check src/controller/revocation.mjs
	node --check src/controller/receipt_required_mcp.mjs
	node --check src/controller/keylime_bootstrap_client.mjs
	node --check src/controller/keylime_mcp_client.mjs
	node --check src/keylime_mcp/attest_and_deploy.mjs
	node --check src/keylime_mcp/config.mjs
	node --check src/keylime_mcp/policy_digest.mjs
	node --check src/controller/permit_signer.mjs
	node --check src/controller/approver_signoff.mjs
	node --check tools/approver.mjs
	node --check experiments/demo3_human_approval.mjs
	node --check experiments/demo3_trials.mjs
	node --check experiments/demo3_model_agent.mjs
	node --check experiments/model_agent_runner.mjs
	node --check experiments/demo3_summary.mjs
	node --check src/keylime_mcp/launch_ledger.mjs
	node --check src/keylime_mcp/mcp_http.mjs
	node --check src/keylime_mcp/permit.mjs
	node --check src/keylime_mcp/server.mjs
	node --check src/keylime_mcp/bootstrap_tenant.mjs
	node --check src/security_parameters.mjs
	node --check src/spire/mtls_proxy.mjs
	node scripts/sync-security-manifest.mjs --check

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

demo2-bootstrap:
	./experiments/demo2_bootstrap.sh

demo2-attestation:
	./experiments/demo2_attestation.sh

drift-policy:
	./experiments/drift_policy.sh

drift-time:
	./experiments/drift_time.sh

drift-revocation:
	./experiments/drift_revocation.sh

drift-identity:
	./experiments/drift_identity.sh

drift: drift-policy drift-time drift-revocation drift-identity

# Demo 3 bound, restart-safe handoff.  Local by default (Linux, no cloud).
demo3-bridge:
	./experiments/demo3_bridge.sh

# The same scenarios against the deployed node: run make demo2-bootstrap and
# infra/aws/prepare-demo.sh first.  Opens its own SSM tunnel.
demo3-bridge-aws:
	./experiments/demo3_bridge.sh --aws results/demo3-bridge-aws.json

# Demo 3 human-in-the-loop: two enrolled people (config/approvers/) sign the
# pending action on their own machines with tools/approver.mjs.  Waits up to
# the approval window for their signoff files in build/approvals/<id>/signoffs/.
demo3-human-approval:
	node experiments/demo3_human_approval.mjs

# Same scenarios with fixture keys generated in-process (automation, labelled).
demo3-human-approval-fixture:
	node experiments/demo3_human_approval.mjs --fixture

# Demo 3 measurement: every bridge scenario 20 times, plus 50 paired latency
# runs (gated path vs direct permitted node call).  Local: real node code with
# a Keylime stand-in.  AWS: same as demo3-bridge-aws prerequisites.
TRIALS ?= 20
LATENCY_RUNS ?= 50
demo3-trials:
	node experiments/demo3_trials.mjs --trials $(TRIALS) --latency-runs $(LATENCY_RUNS)

demo3-trials-aws:
	node experiments/demo3_trials.mjs --aws --trials $(TRIALS) --latency-runs $(LATENCY_RUNS)

# Demo 3 live model-driven request: a Claude model inside nono chooses the
# request; nono's credential proxy holds the key (EC528_ANTHROPIC_API_KEY) and
# the agent gets a phantom token.  Writes results/demo3-model-agent*.json.
demo3-model-agent:
	node experiments/demo3_model_agent.mjs --nono "$(NONO_BINARY)"

# Same, with Claude Code as the agent on a Claude subscription (no API billing):
# EC528_CLAUDE_OAUTH_TOKEN holds the token from `claude setup-token`.
demo3-claude-agent:
	node experiments/demo3_model_agent.mjs --agent claude-code --nono "$(NONO_BINARY)"

# Reproduce the recorded model decision without calling the API.
TRANSCRIPT ?= $(firstword $(wildcard results/demo3-model-agent-claude-code-transcript.json results/demo3-model-agent-transcript.json))
demo3-model-agent-replay:
	node experiments/demo3_model_agent.mjs --nono "$(NONO_BINARY)" --replay "$(TRANSCRIPT)"

# Markdown table of every Demo 3 result in results/, for the design document.
demo3-summary:
	@node experiments/demo3_summary.mjs

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

# Every local (no-cloud) experiment in order, stopping at the first failure.
# Results land in results/; nono must be on PATH (or pass NONO_BINARY=...).
NONO_BINARY ?= $(shell command -v nono)
demo3-local: ci integration-nono demo2-authorization drift-policy drift-time drift-revocation demo3-bridge demo3-human-approval-fixture demo3-trials
	@echo "all local experiments passed; results are in results/"
