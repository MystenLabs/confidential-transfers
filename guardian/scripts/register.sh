#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Register one Pulumi-managed enclave instance and open its readiness gate.
# The active Sui address must be the Guardian operator.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env GUARDIAN_PACKAGE_ID GUARDIAN_ID TOKEN_TYPE
require_commands aws jq
require_guardian_cli

INSTANCE_ID=${1:-}
if [ -z "$INSTANCE_ID" ]; then
    echo "usage: $0 <ec2-instance-id>" >&2
    exit 1
fi

wait_for_ssm "$INSTANCE_ID"

if ssm_run "$INSTANCE_ID" "curl --fail --silent http://127.0.0.1:3000/registered" >/dev/null 2>&1; then
    echo "==> $INSTANCE_ID is already registered"
    exit 0
fi

# If this instance relaunched, remove the slot belonging to its prior enclave
# before registering the newly generated keys.
OLD_KEY_INDEX=$(guardian_key_index "$INSTANCE_ID")
if [ "$OLD_KEY_INDEX" != None ]; then
    echo "==> removing $INSTANCE_ID's previous Guardian key at slot $OLD_KEY_INDEX"
    remove_guardian_key "$OLD_KEY_INDEX"
fi

echo "==> waiting for $INSTANCE_ID attestation"
ATTESTATION=
for _ in $(seq 1 120); do
    if ATTESTATION=$(ssm_run "$INSTANCE_ID" \
        "curl --fail --silent --show-error http://127.0.0.1:3000/attestation" 2>/dev/null); then
        break
    fi
    sleep 10
done
if [ -z "$ATTESTATION" ]; then
    echo "error: $INSTANCE_ID did not expose an attestation within 20 minutes" >&2
    exit 1
fi
DOC_BASE64=$(jq -er '.attestation' <<<"$ATTESTATION")

echo "==> registering $INSTANCE_ID on chain"
REGISTRATION=$(guardian_cli register-enclave \
    --guardian-package "$GUARDIAN_PACKAGE_ID" \
    --guardian "$GUARDIAN_ID" \
    --token-type "$TOKEN_TYPE" \
    --attestation-base64 "$DOC_BASE64")
KEY_INDEX=$(jq -er '.key_index' <<<"$REGISTRATION")

aws ec2 create-tags \
    --region "$AWS_REGION" \
    --resources "$INSTANCE_ID" \
    --tags "Key=GuardianKeyIndex,Value=$KEY_INDEX" "Key=GuardianId,Value=$GUARDIAN_ID"
ssm_run "$INSTANCE_ID" "curl --fail --silent --request POST http://127.0.0.1:3000/registered" >/dev/null
echo "==> $INSTANCE_ID is ready at Guardian key slot $KEY_INDEX"
