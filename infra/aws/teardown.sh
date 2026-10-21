#!/usr/bin/env bash
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

run_aws cloudformation delete-stack \
  --profile "$profile" \
  --region "$region" \
  --stack-name "$stack_name"
run_aws cloudformation wait stack-delete-complete \
  --profile "$profile" \
  --region "$region" \
  --stack-name "$stack_name"
echo "Deleted $stack_name and its EC2, EBS, and security-group resources."
