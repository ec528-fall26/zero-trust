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
if ! git -C "$repository" ls-remote origin | grep -q "$commit_sha"; then
  echo "refusing deployment: the pinned commit is not available from origin" >&2
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
    GitCommitSha="$commit_sha" \
  --tags Project=ec528-zero-trust

run_aws cloudformation describe-stacks \
  --profile "$profile" \
  --region "$region" \
  --stack-name "$stack_name" \
  --query 'Stacks[0].Outputs' \
  --output table
