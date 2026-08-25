#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Converge the Pulumi-managed fleet to an absolute size. Scale-up registers new
# enclaves before adding them to Envoy. Scale-down drains and removes departing
# keys before destroying their instances.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_fleet_operation

TARGET=${1:-}
CONTRA_COMMIT=${2:-}
if ! validate_fleet_spec "$TARGET" "$CONTRA_COMMIT"; then
    echo "usage: $0 <fleet-size: 1-$MAX_ENCLAVE_KEYS> <40-character-contra-commit>" >&2
    exit 1
fi

CURRENT_IDS=()
while IFS= read -r instance_id; do
    CURRENT_IDS+=("$instance_id")
done < <(fleet_instance_ids)
CURRENT=${#CURRENT_IDS[@]}
if [ "$TARGET" -eq "$CURRENT" ]; then
    echo "==> fleet already has $TARGET instances; reconciling infrastructure and registration"
elif [ "$TARGET" -lt "$CURRENT" ]; then
    for ((i = TARGET; i < CURRENT; i++)); do
        "$SCRIPT_DIR/remove.sh" "${CURRENT_IDS[$i]}"
    done
fi

configure_enclave_fleet "$TARGET" "$CONTRA_COMMIT"
deploy_enclave_fleet
register_enclave_fleet

# Envoy uses a static endpoint list, so refresh its task definition after every
# fleet membership change.
deploy_guardian_proxy
echo "==> fleet scaled from $CURRENT to $TARGET instances"
