#!/usr/bin/env bash
# Guided Demo 2 run for screen recording: `make demo-record [STACK=...]`.
#
# Checks everything first, then plays each shot behind a title card and waits
# for Enter between shots, so the person recording controls the pacing.
# Needs a deployed stack (infra/aws/deploy.sh --apply). It never creates or
# deletes AWS resources. The IMA shot leaves the node failed on purpose, so
# tear the stack down afterwards.
set -euo pipefail

stack=${1:-ec528-zero-trust-demo}
case "$stack" in
  ec528-zero-trust-*) ;;
  *) echo "stack name must begin with ec528-zero-trust-" >&2; exit 64 ;;
esac
repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repository"
export AWS_PROFILE=${AWS_PROFILE:-ec528-deployer}
export AWS_REGION=${AWS_REGION:-us-east-2}
python=${PYTHON_BIN:-$repository/.venv/bin/python}
[ -x "$python" ] || python=python3
output="$repository/build/demo-record/$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$output"
jaeger_ui=http://127.0.0.1:16686
mcp_url=http://127.0.0.1:3000/mcp
token_file="$repository/build/aws-keylime/mcp-token"
total_shots=4
background_pids=()

bold=$(tput bold 2>/dev/null || true)
dim=$(tput dim 2>/dev/null || true)
green=$(tput setaf 2 2>/dev/null || true)
red=$(tput setaf 1 2>/dev/null || true)
yellow=$(tput setaf 3 2>/dev/null || true)
reset=$(tput sgr0 2>/dev/null || true)

clear_screen() { clear 2>/dev/null || printf '\n\n'; }
ok() { printf '  %s✓%s %s\n' "$green" "$reset" "$1"; }
warn() { printf '  %s!%s %s\n' "$yellow" "$reset" "$1"; }
die() { printf '  %s✗%s %s\n' "$red" "$reset" "$1" >&2; exit 1; }
pause() { printf '\n  %s%s — press Enter%s ' "$dim" "${1:-Continue}" "$reset"; read -r _; }
open_url() { if command -v open >/dev/null; then open "$1"; else xdg-open "$1" >/dev/null 2>&1 & fi; }

title() {
  local number=$1 heading=$2
  shift 2
  clear_screen
  printf '\n\n  %sShot %s of %s%s\n\n' "$dim" "$number" "$total_shots" "$reset"
  printf '  %s%s%s\n\n' "$bold" "$heading" "$reset"
  for line in "$@"; do printf '  %s\n' "$line"; done
  printf '\n'
}

run_aws() {
  if [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    local expat_prefix
    expat_prefix=$(brew --prefix expat 2>/dev/null || true)
    if [ -n "$expat_prefix" ]; then
      env DYLD_LIBRARY_PATH="$expat_prefix/lib" aws "$@"
      return
    fi
  fi
  aws "$@"
}

kill_tree() {
  local pid=$1 child
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do kill_tree "$child"; done
  kill "$pid" 2>/dev/null || true
}

cleanup() {
  local pid
  for pid in "${background_pids[@]:-}"; do
    if [ -n "$pid" ]; then kill_tree "$pid"; fi
  done
  return 0
}
trap cleanup EXIT INT TERM

ssm_status() {
  local command_id status
  command_id=$(run_aws ssm send-command --instance-ids "$instance_id" \
    --document-name AWS-RunShellScript \
    --parameters '{"commands":["/usr/local/libexec/ec528-keylime-status"]}' \
    --query Command.CommandId --output text)
  for _attempt in $(seq 1 30); do
    status=$(run_aws ssm get-command-invocation --command-id "$command_id" \
      --instance-id "$instance_id" --query Status --output text 2>/dev/null || echo Pending)
    case "$status" in Success|Failed|TimedOut|Cancelled) break ;; esac
    sleep 2
  done
  run_aws ssm get-command-invocation --command-id "$command_id" \
    --instance-id "$instance_id" --query StandardOutputContent --output text \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["results"].get("attestation_status"))'
}

summarize() {
  python3 - "$1" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
for scenario in result.get("scenarios", []):
    observed = scenario.get("observed") or {}
    detail = observed.get("reason") or observed.get("status") or ""
    keylime = (observed.get("keylime") or {}).get("attestation_status")
    if keylime:
        detail = f"Keylime {keylime}"
    mark = "\033[32m✓\033[0m" if scenario.get("passed") else "\033[31m✗\033[0m"
    print(f"  {mark} {scenario['name'].replace('_', ' ')}  {detail}")
print(f"\n  Overall: {result.get('status', 'unknown').upper()}")
PY
}

start_tunnel() {
  PATH=$tunnel_path ./infra/aws/open-tunnel.sh "$stack" >"$output/tunnel.log" 2>&1 &
  background_pids+=("$!")
  local tunnel_pid=$!
  for _attempt in $(seq 1 60); do
    curl -sf -o /dev/null --max-time 1 http://127.0.0.1:3000/healthz && return 0
    kill -0 "$tunnel_pid" 2>/dev/null || die "SSM tunnel exited (see $output/tunnel.log)"
    sleep 0.5
  done
  die "SSM tunnel did not become ready"
}

stop_background() {
  cleanup
  background_pids=()
  sleep 1
}

# ---------------------------------------------------------------- preflight
clear_screen
printf '\n  %sPreflight%s  (stack %s, region %s)\n\n' "$bold" "$reset" "$stack" "$AWS_REGION"
case "$repository" in
  /tmp/*|/private/tmp/*|/var/*|/private/var/*)
    die "This checkout is in a folder nono lets the sandbox read ($repository). Clone it under your home folder, e.g. ~/ec528-demo." ;;
esac
case "$repository" in
  "$HOME/Documents"*|"$HOME/Desktop"*|*"Mobile Documents"*)
    warn "This checkout may be in iCloud Drive; commands can stall for a minute. Prefer a clone outside it." ;;
esac
for tool in node nono aws docker curl python3; do
  command -v "$tool" >/dev/null || die "$tool is not installed"
done
ok "node, nono, aws, docker, curl found"
"$python" -c 'import jsonschema' 2>/dev/null || die "$python cannot import jsonschema (run: .venv/bin/pip install -e .)"
ok "Python environment ready"
# The plugin directory is added to PATH only for the tunnel command. nono's
# --strict-broker-path refuses to start if any PATH entry is writable from
# inside the sandbox (for example a plugin unpacked under /tmp).
tunnel_path=$PATH
if [ -n "${SESSION_MANAGER_PLUGIN_BIN:-}" ]; then
  [ -x "$SESSION_MANAGER_PLUGIN_BIN" ] || die "SESSION_MANAGER_PLUGIN_BIN is not executable"
  tunnel_path="$(dirname "$SESSION_MANAGER_PLUGIN_BIN"):$PATH"
fi
PATH=$tunnel_path command -v session-manager-plugin >/dev/null \
  || die "AWS Session Manager plugin not found (install it, or set SESSION_MANAGER_PLUGIN_BIN)"
ok "Session Manager plugin found"
if ! curl -sf -o /dev/null --max-time 2 "$jaeger_ui"; then
  make -s jaeger >/dev/null
  for _attempt in $(seq 1 30); do curl -sf -o /dev/null --max-time 1 "$jaeger_ui" && break; sleep 1; done
fi
curl -sf -o /dev/null --max-time 2 "$jaeger_ui" || die "Jaeger is not reachable at $jaeger_ui"
ok "Jaeger running at $jaeger_ui"
instance_id=$(run_aws cloudformation describe-stacks --stack-name "$stack" \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]" --output text 2>/dev/null || true)
case "$instance_id" in
  i-*) ok "Stack $stack is up ($instance_id)" ;;
  *) die "Stack $stack not found. Deploy first: ./infra/aws/deploy.sh --apply $stack" ;;
esac
if [ ! -s "$token_file" ]; then
  ./infra/aws/fetch-token.sh "$stack" >/dev/null
fi
ok "MCP token present (not displayed)"
attestation=$(ssm_status)
[ "$attestation" = "PASS" ] || die "Keylime status is $attestation, expected PASS"
ok "Keylime reports PASS for the node"
printf '\n  Output for this take: %s\n' "${output#"$repository"/}"
pause "Preflight passed. Start your screen recording, then"

# ---------------------------------------------------------------- shot 1
title 1 "The agent is sandboxed" \
  "The AI agent runs inside nono. Its only way out is writing a request" \
  "file. We try every other path and check that each one is blocked."
pause "Run the confinement checks"
make -s integration-nono PYTHON="$python" NONO_BINARY="$(command -v nono)" 2>/dev/null \
  | tail -n 1 > "$output/confinement.json"
python3 - "$output/confinement.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
for case in result["results"]:
    mark = "\033[32m✓\033[0m" if case["passed"] else "\033[31m✗\033[0m"
    print(f"  {mark} {case['case'].replace('_', ' ')}")
print(f"\n  {sum(c['passed'] for c in result['results'])}/{len(result['results'])} passed")
PY
pause

# ---------------------------------------------------------------- shot 2
title 2 "Two of three people must approve" \
  "A browser dashboard plays the approvers. Behind it, the approved job runs" \
  "on the AWS machine only after Keylime says the machine is healthy." \
  "" \
  "Click, in order:" \
  "  1. Try without receipt        -> refused" \
  "  2. Approve as operator        -> still pending (1 of 3)" \
  "  3. Approve as security        -> receipt issued (2 of 3)" \
  "  4. Try altered target         -> refused" \
  "  5. Run approved workload      -> runs on AWS, Keylime verdict trusted" \
  "  6. Replay receipt             -> refused"
pause "Open the dashboard"
start_tunnel
token=$(cat "$token_file")
KEYLIME_MCP_URL=$mcp_url KEYLIME_MCP_TOKEN=$token KEYLIME_MCP_ALLOW_INSECURE_LOOPBACK=1 \
  PYTHONPATH="$repository/src" "$python" -u experiments/live_demo.py --skip-confinement \
  >"$output/dashboard.log" 2>&1 &
background_pids+=("$!")
unset token
for _attempt in $(seq 1 40); do grep -qi 'live demo:' "$output/dashboard.log" && break; sleep 0.5; done
grep -qi 'live demo:' "$output/dashboard.log" || die "dashboard did not start (see $output/dashboard.log)"
ok "$(grep -i 'live demo:' "$output/dashboard.log" | tail -n 1)"
pause "When you have clicked through all six steps"
stop_background

# ---------------------------------------------------------------- shot 3
title 3 "The whole chain, traced live (optional, about 2.5 minutes)" \
  "One continuous run: sandbox, watcher, two signatures, AWS, Keylime." \
  "Then Keylime is stopped on purpose: the next request must fail." \
  "Watch the trace fill in on the right."
printf '  Run shot 3? [y/N] '
read -r answer
if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
  open_url "$jaeger_ui/search?service=ec528-demo2-end-to-end&lookback=1h"
  OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 AWS_STACK_NAME=$stack \
    PYTHON_BIN="$python" NONO_BIN="$(command -v nono)" KEYLIME_MCP_TOKEN_FILE="$token_file" \
    node experiments/demo2_end_to_end.mjs "$output/demo2-end-to-end.json" >/dev/null 2>"$output/e2e.log" || true
  summarize "$output/demo2-end-to-end.json"
  pause
fi

# ---------------------------------------------------------------- shot 4
title 4 "Catching a tampered machine" \
  "Linux fingerprints every program the machine runs (IMA), and Keylime" \
  "checks them against an approved list. We run the approved job, then a" \
  "program that is not on the list. Keylime should flag the machine, and the" \
  "next approved request should be denied."
pause "Run the tamper test"
open_url "$jaeger_ui/search?service=ec528-ima-tamper&lookback=1h"
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 AWS_STACK_NAME=$stack \
  KEYLIME_MCP_TOKEN_FILE="$token_file" \
  node experiments/ima_tamper.mjs "$output/ima-tamper.json" >/dev/null 2>"$output/ima.log" || true
summarize "$output/ima-tamper.json"
pause

# ---------------------------------------------------------------- end
clear_screen
printf '\n\n  %sDone%s\n\n' "$bold" "$reset"
printf '  Results for this take: %s\n' "${output#"$repository"/}"
printf '  The node is now marked failed on purpose. Tear it down with:\n\n'
printf '    ./infra/aws/teardown.sh %s\n\n' "$stack"
