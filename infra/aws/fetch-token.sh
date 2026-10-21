#!/usr/bin/env bash
# Copy the node's Keylime MCP bearer token to build/aws-keylime/mcp-token
# (mode 0600, ignored by Git) so the experiments and dashboard can call it.
#
# The token travels through Systems Manager, so its value is stored in this
# account's SSM command history. It is generated per instance and becomes
# useless once the stack is torn down, but never show that command's output.
set -euo pipefail

stack_name=${1:-ec528-zero-trust-demo}
case "$stack_name" in
  ec528-zero-trust-*) ;;
  *) echo "stack name must begin with ec528-zero-trust-" >&2; exit 64 ;;
esac
profile=${AWS_PROFILE:-ec528-deployer}
region=${AWS_REGION:-us-east-2}

run_aws() {
  if [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    expat_prefix=$(brew --prefix expat 2>/dev/null || true)
    if [ -n "$expat_prefix" ]; then
      env DYLD_LIBRARY_PATH="$expat_prefix/lib" aws "$@"
      return
    fi
  fi
  aws "$@"
}

repository=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
instance_id=$(run_aws cloudformation describe-stacks \
  --profile "$profile" \
  --region "$region" \
  --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]" \
  --output text)
case "$instance_id" in
  i-*) ;;
  *) echo "could not resolve the demo instance" >&2; exit 66 ;;
esac

command_id=$(run_aws ssm send-command \
  --profile "$profile" \
  --region "$region" \
  --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript \
  --comment "ec528 fetch MCP token (do not display output)" \
  --parameters '{"commands":["cat /etc/ec528-keylime-mcp-token"]}' \
  --query 'Command.CommandId' \
  --output text)

status=Pending
for _attempt in $(seq 1 30); do
  status=$(run_aws ssm get-command-invocation \
    --profile "$profile" \
    --region "$region" \
    --command-id "$command_id" \
    --instance-id "$instance_id" \
    --query Status \
    --output text 2>/dev/null || echo Pending)
  case "$status" in
    Success|Failed|TimedOut|Cancelled|Cancelling) break ;;
  esac
  sleep 2
done
[ "$status" = "Success" ] || { echo "token fetch failed: $status" >&2; exit 70; }

output_directory="$repository/build/aws-keylime"
install -d -m 0700 "$output_directory"
umask 077
temporary=$(mktemp "$output_directory/mcp-token.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
run_aws ssm get-command-invocation \
  --profile "$profile" \
  --region "$region" \
  --command-id "$command_id" \
  --instance-id "$instance_id" \
  --query StandardOutputContent \
  --output text | tr -d '\n' > "$temporary"
length=$(wc -c < "$temporary" | tr -d ' ')
[ "$length" -ge 32 ] || { echo "token fetch returned an unexpected value" >&2; exit 70; }
mv "$temporary" "$output_directory/mcp-token"
trap - EXIT HUP INT TERM
echo "token saved to build/aws-keylime/mcp-token ($length bytes, mode 0600)"
