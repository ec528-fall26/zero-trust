#!/usr/bin/env bash
# Switch a freshly deployed NitroTPM node from swtpm to its hardware TPM.
# Run from the controller (your machine), after deploying with a NitroTPM AMI
# and before `make demo2-bootstrap`:
#
#   AMI_ID=<id from build-nitrotpm-ami.sh> ./infra/aws/deploy.sh --apply
#   ./infra/aws/enable-nitrotpm.sh [stack]
#
# NitroTPM has no EK certificate from a TPM vendor CA, so Keylime's default
# EK-certificate check cannot pass.  Instead of disabling EK checking, this pins
# the EK that the EC2 API reports for *this instance* (GetInstanceTpmEkPub, read
# here with the deployer's credentials, outside the node) and installs a
# Keylime ek_check_script that only accepts an agent presenting that EK.
set -euo pipefail

stack_name=${1:-ec528-zero-trust-demo}
case "$stack_name" in
  ec528-zero-trust-*) ;;
  *) echo "stack name must begin with ec528-zero-trust-" >&2; exit 64 ;;
esac
profile=${AWS_PROFILE:-ec528-deployer}
region=${AWS_REGION:-us-east-2}
aws_() { aws --profile "$profile" --region "$region" "$@"; }

instance_id=$(aws_ cloudformation describe-stacks --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]" --output text)
case "$instance_id" in
  i-*) ;;
  *) echo "could not resolve the demo instance" >&2; exit 66 ;;
esac
image_id=$(aws_ ec2 describe-instances --instance-ids "$instance_id" \
  --query 'Reservations[0].Instances[0].ImageId' --output text)
tpm_support=$(aws_ ec2 describe-images --image-ids "$image_id" \
  --query 'Images[0].TpmSupport' --output text)
if [ "$tpm_support" != "v2.0" ]; then
  echo "$instance_id runs $image_id, which has no NitroTPM; deploy with AMI_ID from build-nitrotpm-ami.sh" >&2
  exit 69
fi

# The trust anchor: the EC2 control plane's record of this instance's EK.
ek_der_b64=$(aws_ ec2 get-instance-tpm-ek-pub --instance-id "$instance_id" \
  --key-type rsa-2048 --key-format der --query KeyValue --output text)
expected_ek_sha256=$(printf '%s' "$ek_der_b64" | base64 -d | sha256sum | cut -d' ' -f1)
echo "EC2 reports EK (rsa-2048) sha256:$expected_ek_sha256 for $instance_id" >&2

ek_check_script=$(cat <<'PY'
#!/usr/bin/python3
# Keylime ek_check_script: accept only the EK pinned from the EC2 API.
import base64, hashlib, os, re, sys
expected = open("/var/lib/ec528/expected-ek-sha256", encoding="ascii").read().strip()
pem = os.environ.get("EK", "")
body = re.sub(r"-----[A-Z ]+-----|\s", "", pem)
try:
    observed = hashlib.sha256(base64.b64decode(body, validate=True)).hexdigest() if body else ""
except ValueError:
    observed = ""
if observed and observed == expected:
    print(f"EK matches the EC2-reported NitroTPM EK sha256:{expected}")
    sys.exit(0)
print(f"EK mismatch: expected sha256:{expected}, agent presented sha256:{observed or 'none'}")
sys.exit(1)
PY
)

commands=$(EXPECTED="$expected_ek_sha256" SCRIPT_B64=$(printf '%s' "$ek_check_script" | base64 | tr -d '\n') node -e '
const expected = process.env.EXPECTED;
if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error("bad EK digest");
const commands = [
  "set -eu",
  "test -c /dev/tpmrm0",
  "test -s /sys/kernel/security/tpm0/binary_bios_measurements",
  "test \"$(cat /var/lib/ec528-bootstrap-result)\" = keylime-bootstrap-pending",
  // Preflight: the TPM in this instance must hold the EK that EC2 reported.
  "tpm2_createek -T device:/dev/tpmrm0 -c /tmp/ec528-ek.ctx -G rsa -u /tmp/ec528-ek.pem -f pem >/dev/null",
  "observed=$(openssl pkey -pubin -in /tmp/ec528-ek.pem -outform DER | sha256sum | cut -d\" \" -f1)",
  "rm -f /tmp/ec528-ek.ctx /tmp/ec528-ek.pem",
  `test \"$observed\" = ${expected} || { echo \"local TPM EK $observed does not match EC2 EK ${expected}\" >&2; exit 65; }`,
  "mkdir -p /var/lib/ec528 && install -d -o root -g root -m 0755 /usr/local/libexec /etc/keylime/tenant.conf.d",
  `printf %s ${expected} > /var/lib/ec528/expected-ek-sha256`,
  "chmod 0644 /var/lib/ec528/expected-ek-sha256",
  `printf %s ${process.env.SCRIPT_B64} | base64 -d > /usr/local/libexec/ec528-ek-check`,
  "chmod 0755 /usr/local/libexec/ec528-ek-check",
  "printf \"[tenant]\\nrequire_ek_cert = False\\nek_check_script = /usr/local/libexec/ec528-ek-check\\n\" > /etc/keylime/tenant.conf.d/20-nitrotpm-ek.conf",
  "bash /opt/ec528-zero-trust/infra/aws/enable-hardware-tpm.sh",
  "echo nitrotpm-enabled ek_sha256=$observed",
];
process.stdout.write(JSON.stringify({ commands, executionTimeout: ["300"] }));
')

command_id=$(aws_ ssm send-command --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript --comment "ec528 enable NitroTPM" \
  --parameters "$commands" --query Command.CommandId --output text)
for _attempt in $(seq 1 60); do
  status=$(aws_ ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" \
    --query Status --output text 2>/dev/null || echo Pending)
  case "$status" in
    Success|Failed|Cancelled|TimedOut) break ;;
  esac
  sleep 5
done
aws_ ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" \
  --query '[StandardOutputContent,StandardErrorContent]' --output text
[ "$status" = Success ] || { echo "enable-nitrotpm failed: $status" >&2; exit 1; }
echo "NitroTPM active on $instance_id. Next: make demo2-bootstrap, then run experiments with KEYLIME_TPM_TYPE=nitrotpm" >&2
