#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: deploy.sh [--apply] [STACK_NAME]" >&2
  exit 64
}

apply=false
if [ "${1:-}" = "--apply" ]; then
  apply=true
  shift
fi
[ "$#" -le 1 ] || usage

stack_name=${1:-ec528-zero-trust-demo}
case "$stack_name" in
  ec528-zero-trust-*) ;;
  *) echo "stack name must begin with ec528-zero-trust-" >&2; exit 64 ;;
esac

command -v aws >/dev/null 2>&1 || { echo "AWS CLI is required" >&2; exit 69; }

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
template="$repository/infra/aws/main.yaml"
profile=${AWS_PROFILE:-ec528-deployer}
region=${AWS_REGION:-us-east-2}
commit_sha=$(git -C "$repository" rev-parse HEAD)

if command -v cfn-lint >/dev/null 2>&1; then
  cfn-lint "$template"
elif command -v uvx >/dev/null 2>&1; then
  uvx cfn-lint "$template"
else
  echo "cfn-lint or uvx is required for fail-closed local template validation" >&2
  exit 69
fi

run_aws sts get-caller-identity --profile "$profile" --region "$region" >/dev/null

vpc_id=$(run_aws ec2 describe-vpcs \
  --profile "$profile" \
  --region "$region" \
  --filters Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' \
  --output text)
subnet_id=$(run_aws ec2 describe-subnets \
  --profile "$profile" \
  --region "$region" \
  --filters Name=vpc-id,Values="$vpc_id" Name=default-for-az,Values=true \
  --query 'sort_by(Subnets,&AvailabilityZone)[0].SubnetId' \
  --output text)

[ "$vpc_id" != "None" ] && [ "$subnet_id" != "None" ] || {
  echo "default VPC and subnet are required" >&2
  exit 66
}

if [ "$apply" = false ]; then
  echo "VALIDATION ONLY: no AWS resources were created."
  echo "stack=$stack_name region=$region vpc=$vpc_id subnet=$subnet_id commit=$commit_sha"
  echo "Run with --apply only after approving EC2 and EBS charges."
  exit 0
fi

if [ -n "$(git -C "$repository" status --porcelain)" ]; then
  echo "refusing deployment: the working tree contains code not present in the pinned commit" >&2
  exit 65
fi
run_aws cloudformation deploy \
  --profile "$profile" \
  --region "$region" \
  --stack-name "$stack_name" \
  --template-file "$template" \
  --parameter-overrides \
    VpcId="$vpc_id" \
    SubnetId="$subnet_id" \
    SourceRevision="$commit_sha" \
  --tags Project=ec528-zero-trust

instance_id=$(run_aws cloudformation describe-stacks \
  --profile "$profile" \
  --region "$region" \
  --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]" \
  --output text)

for _attempt in $(seq 1 60); do
  ping_status=$(run_aws ssm describe-instance-information \
    --profile "$profile" \
    --region "$region" \
    --filters Key=InstanceIds,Values="$instance_id" \
    --query 'InstanceInformationList[0].PingStatus' \
    --output text)
  [ "$ping_status" = "Online" ] && break
  sleep 10
done
[ "${ping_status:-}" = "Online" ] || {
  echo "instance did not become available in Systems Manager" >&2
  exit 75
}

bundle=$(mktemp /tmp/ec528-mcp-bundle.XXXXXX)
trap 'rm -f "$bundle"' EXIT HUP INT TERM
tar -C "$repository" -czf "$bundle" \
  package.json \
  package-lock.json \
  src/keylime_mcp \
  infra/aws/install-mcp.sh
bundle_base64=$(base64 < "$bundle" | tr -d '\n')
parameters=$(BUNDLE_BASE64="$bundle_base64" node -e '
const payload = process.env.BUNDLE_BASE64;
const commands = [
  "set -eu",
  "install -d -o root -g root -m 0755 /opt/ec528-zero-trust",
  `printf %s ${JSON.stringify(payload)} | base64 --decode | tar -xzf - -C /opt/ec528-zero-trust`,
  "bash /opt/ec528-zero-trust/infra/aws/install-mcp.sh d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
];
process.stdout.write(JSON.stringify({ commands, executionTimeout: ["900"] }));
')
command_id=$(run_aws ssm send-command \
  --profile "$profile" \
  --region "$region" \
  --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript \
  --timeout-seconds 600 \
  --parameters "$parameters" \
  --query 'Command.CommandId' \
  --output text)

# `aws ssm wait command-executed` gives up after about 100 seconds, but the
# install waits up to 10 minutes for the Keylime bootstrap.  Poll until the
# invocation reaches a terminal status, for up to 15 minutes.
installation_status=Pending
for _attempt in $(seq 1 90); do
  installation_status=$(run_aws ssm get-command-invocation \
    --profile "$profile" \
    --region "$region" \
    --command-id "$command_id" \
    --instance-id "$instance_id" \
    --query Status \
    --output text 2>/dev/null || echo Pending)
  case "$installation_status" in
    Success|Failed|TimedOut|Cancelled|Cancelling) break ;;
  esac
  sleep 10
done
[ "$installation_status" = "Success" ] || {
  echo "MCP installation did not succeed: $installation_status" >&2
  run_aws ssm get-command-invocation \
    --profile "$profile" \
    --region "$region" \
    --command-id "$command_id" \
    --instance-id "$instance_id" \
    --query StandardErrorContent \
    --output text >&2 || true
  exit 70
}

run_aws cloudformation describe-stacks \
  --profile "$profile" \
  --region "$region" \
  --stack-name "$stack_name" \
  --query 'Stacks[0].Outputs' \
  --output table
