#!/usr/bin/env bash
set -euo pipefail

apply=false
if [ "${1:-}" = --apply ]; then
  apply=true
  shift
fi
[ "$#" -eq 0 ] || { echo "usage: setup-prerequisites.sh [--apply]" >&2; exit 64; }

profile=${AWS_PROFILE:-ec528-deployer}
role_name=${EC528_INSTANCE_ROLE:-EC528ZeroTrustInstanceRole}
instance_profile=${EC528_INSTANCE_PROFILE:-EC528ZeroTrustInstanceProfile}
command -v aws >/dev/null 2>&1 || { echo "AWS CLI v2 is required" >&2; exit 69; }

run_aws() {
  if [ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1; then
    expat_prefix=$(brew --prefix expat 2>/dev/null || true)
    if [ -n "$expat_prefix" ]; then
      env DYLD_LIBRARY_PATH="$expat_prefix/lib" aws "$@"
      return
    fi
  fi
  aws "$@"
}

run_aws sts get-caller-identity --profile "$profile" >/dev/null || {
  echo "AWS profile '$profile' is not authenticated; run: aws configure sso --profile $profile" >&2
  exit 77
}

iam_error=$(mktemp /tmp/ec528-iam-check.XXXXXX)
trap 'rm -f -- "$iam_error"' EXIT HUP INT TERM
if run_aws iam get-instance-profile --profile "$profile" \
  --instance-profile-name "$instance_profile" >/dev/null 2>"$iam_error"; then
  echo "ready: IAM instance profile $instance_profile exists"
  exit 0
fi

if grep -q 'AccessDenied' "$iam_error"; then
  echo "cannot validate IAM instance profile $instance_profile: profile '$profile' lacks iam:GetInstanceProfile" >&2
  echo "run this check with an administrator profile; do not infer that the instance profile is missing" >&2
  exit 77
fi

if [ "$apply" = false ]; then
  echo "missing: IAM instance profile $instance_profile"
  echo "validation only; run with --apply to create its EC2 role and attach AmazonSSMManagedInstanceCore"
  exit 66
fi

trust_policy=$(mktemp /tmp/ec528-ec2-trust.XXXXXX.json)
trap 'rm -f -- "$iam_error" "$trust_policy"' EXIT HUP INT TERM
cat > "$trust_policy" <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
JSON

if ! run_aws iam get-role --profile "$profile" --role-name "$role_name" >/dev/null 2>&1; then
  run_aws iam create-role --profile "$profile" --role-name "$role_name" \
    --assume-role-policy-document "file://$trust_policy" >/dev/null
fi
run_aws iam attach-role-policy --profile "$profile" --role-name "$role_name" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
run_aws iam create-instance-profile --profile "$profile" \
  --instance-profile-name "$instance_profile" >/dev/null
run_aws iam add-role-to-instance-profile --profile "$profile" \
  --instance-profile-name "$instance_profile" --role-name "$role_name"
echo "created: $instance_profile (AWS may take several seconds to propagate it)"
