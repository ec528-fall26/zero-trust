#!/usr/bin/env bash
set -euo pipefail

stack_name=${1:-ec528-zero-trust-demo}
case "$stack_name" in
  ec528-zero-trust-*) ;;
  *) echo "stack name must begin with ec528-zero-trust-" >&2; exit 64 ;;
esac

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
profile=${AWS_PROFILE:-ec528-deployer}
region=${AWS_REGION:-us-east-2}
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

ping_status=$(run_aws ssm describe-instance-information \
  --profile "$profile" \
  --region "$region" \
  --filters Key=InstanceIds,Values="$instance_id" \
  --query 'InstanceInformationList[0].PingStatus' \
  --output text)
[ "$ping_status" = "Online" ] || {
  echo "instance is not online in Systems Manager: $ping_status" >&2
  exit 75
}

command_id=$(run_aws ssm send-command \
  --profile "$profile" \
  --region "$region" \
  --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript \
  --parameters "file://$repository/infra/aws/action-command.json" \
  --query 'Command.CommandId' \
  --output text)
run_aws ssm wait command-executed \
  --profile "$profile" \
  --region "$region" \
  --command-id "$command_id" \
  --instance-id "$instance_id"

status=$(run_aws ssm get-command-invocation \
  --profile "$profile" \
  --region "$region" \
  --command-id "$command_id" \
  --instance-id "$instance_id" \
  --query Status \
  --output text)
[ "$status" = "Success" ] || {
  echo "remote action preparation failed: $status" >&2
  exit 70
}

output_directory="$repository/build/aws-keylime"
install -d -m 0700 "$output_directory"
temporary=$(mktemp "$output_directory/action.json.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
run_aws ssm get-command-invocation \
  --profile "$profile" \
  --region "$region" \
  --command-id "$command_id" \
  --instance-id "$instance_id" \
  --query StandardOutputContent \
  --output text > "$temporary"
python3 -m json.tool "$temporary" >/dev/null
chmod 0600 "$temporary"
mv "$temporary" "$output_directory/action.json"
trap - EXIT HUP INT TERM

printf '%s\n' "instance_id=$instance_id"
printf '%s\n' "action_file=$output_directory/action.json"
printf '%s\n' "The MCP bearer token remains only on the instance until explicitly retrieved."
