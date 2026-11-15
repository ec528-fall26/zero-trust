#!/usr/bin/env bash
# Build a NitroTPM-enabled copy of the pinned AlmaLinux 10 AMI (one time).
#
# NitroTPM can only be enabled when an AMI is registered (RegisterImage with
# --tpm-support v2.0 --boot-mode uefi); it cannot be added to an existing AMI or
# instance.  This copies the source AMI into the account so we own its root
# snapshot, then registers that snapshot as a new AMI with NitroTPM.
#
#   AWS_PROFILE=ec528-deployer ./infra/aws/build-nitrotpm-ami.sh [source-ami]
#
# Prints the new AMI id.  Deploy with: AMI_ID=<id> ./infra/aws/deploy.sh --apply
# The AMI and its snapshot cost a little EBS storage until deregistered; see the
# cleanup commands at the end.
set -euo pipefail

source_ami=${1:-ami-0281f4b4279b17b5b}
profile=${AWS_PROFILE:-ec528-deployer}
region=${AWS_REGION:-us-east-2}
stamp=$(date -u +%Y%m%dT%H%M%SZ)

aws_() { aws --profile "$profile" --region "$region" "$@"; }

read -r arch root_device boot_mode tpm_support < <(aws_ ec2 describe-images \
  --image-ids "$source_ami" \
  --query 'Images[0].[Architecture,RootDeviceName,BootMode,TpmSupport]' \
  --output text)
echo "source $source_ami: arch=$arch root=$root_device boot_mode=$boot_mode tpm=$tpm_support" >&2
if [ "$tpm_support" = "v2.0" ]; then
  echo "$source_ami already has NitroTPM support; deploy it directly" >&2
  echo "$source_ami"
  exit 0
fi
if [ "$boot_mode" = "legacy-bios" ]; then
  echo "WARNING: source AMI is legacy-bios only; it may not boot under UEFI" >&2
fi

instance_type=${INSTANCE_TYPE:-t3.small}
nitro_tpm=$(aws_ ec2 describe-instance-types --instance-types "$instance_type" \
  --query 'InstanceTypes[0].NitroTpmSupport' --output text)
if [ "$nitro_tpm" != "supported" ]; then
  echo "$instance_type does not support NitroTPM ($nitro_tpm); choose another InstanceType" >&2
  exit 69
fi

echo "copying $source_ami into this account..." >&2
copy_id=$(aws_ ec2 copy-image \
  --source-image-id "$source_ami" \
  --source-region "$region" \
  --name "ec528-alma10-copy-$stamp" \
  --query ImageId --output text)
aws_ ec2 wait image-available --image-ids "$copy_id"
snapshot_id=$(aws_ ec2 describe-images --image-ids "$copy_id" \
  --query "Images[0].BlockDeviceMappings[?DeviceName=='$root_device'].Ebs.SnapshotId | [0]" \
  --output text)
case "$snapshot_id" in
  snap-*) ;;
  *) echo "could not find the root snapshot of $copy_id" >&2; exit 66 ;;
esac

echo "registering $snapshot_id with NitroTPM v2.0 and UEFI boot..." >&2
ami_id=$(aws_ ec2 register-image \
  --name "ec528-alma10-nitrotpm-$stamp" \
  --description "EC528 AlmaLinux 10 from $source_ami with NitroTPM v2.0 (UEFI)" \
  --architecture "$arch" \
  --virtualization-type hvm \
  --boot-mode uefi \
  --tpm-support v2.0 \
  --ena-support \
  --root-device-name "$root_device" \
  --block-device-mappings "DeviceName=$root_device,Ebs={SnapshotId=$snapshot_id,VolumeType=gp3,DeleteOnTermination=true}" \
  --query ImageId --output text)
aws_ ec2 wait image-available --image-ids "$ami_id"

# The intermediate copy is no longer needed; its snapshot backs the new AMI.
aws_ ec2 deregister-image --image-id "$copy_id" >/dev/null

aws_ ec2 describe-images --image-ids "$ami_id" \
  --query 'Images[0].[ImageId,BootMode,TpmSupport]' --output text >&2
cat >&2 <<EOF

Deploy:   AMI_ID=$ami_id ./infra/aws/deploy.sh --apply
Cleanup:  aws ec2 deregister-image --image-id $ami_id
          aws ec2 delete-snapshot --snapshot-id $snapshot_id
EOF
echo "$ami_id"
