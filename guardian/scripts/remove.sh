#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Drain one enclave instance and remove its registered Guardian key. This does
# not delete the Pulumi-managed EC2 instance; use scale.sh to change fleet size.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env GUARDIAN_PACKAGE_ID GUARDIAN_ID TOKEN_TYPE
require_commands aws jq sui

INSTANCE_ID=${1:-}
if [ -z "$INSTANCE_ID" ]; then
    echo "usage: $0 <ec2-instance-id>" >&2
    exit 1
fi

wait_for_ssm "$INSTANCE_ID"
KEY_INDEX=$(guardian_key_index "$INSTANCE_ID")
if [ "$KEY_INDEX" = None ]; then
    echo "error: $INSTANCE_ID has no GuardianKeyIndex tag" >&2
    exit 1
fi

# Stop ingress first so the proxy marks the instance unhealthy before its key
# is removed. Pulumi will recreate the bridge if the host is reprovisioned.
echo "==> draining $INSTANCE_ID"
ssm_run "$INSTANCE_ID" "systemctl stop contra-guardian-bridge.service" >/dev/null
echo "==> removing Guardian key at slot $KEY_INDEX"
remove_guardian_key "$KEY_INDEX"
aws ec2 delete-tags \
    --region "$AWS_REGION" \
    --resources "$INSTANCE_ID" \
    --tags Key=GuardianKeyIndex Key=GuardianId
echo "==> $INSTANCE_ID drained and its key removed"
