#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Provision the initial fleet, register every enclave, deploy the proxy, and set
# the Guardian URL. The Guardian object and operator must already exist.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_fleet_operation

COUNT=${1:-}
CONTRA_COMMIT=${2:-}
if ! validate_fleet_spec "$COUNT" "$CONTRA_COMMIT"; then
    echo "usage: $0 <fleet-size: 1-$MAX_ENCLAVE_KEYS> <40-character-contra-commit>" >&2
    exit 1
fi
configure_enclave_fleet "$COUNT" "$CONTRA_COMMIT"

echo "==> provisioning enclave hosts"
deploy_enclave_fleet
register_enclave_fleet

echo "==> deploying the proxy"
deploy_guardian_proxy
URL=$(pulumi_output "$PROXY_SERVICE_DIR" process_request_url | jq -er '.')

echo "==> setting Guardian URL to $URL"
sui client ptb \
    --move-call "$GUARDIAN_PACKAGE_ID::guardian::set_url" "<$TOKEN_TYPE>" \
        @"$GUARDIAN_ID" "'$URL'" \
    --gas-budget "$SUI_GAS_BUDGET" >/dev/null

echo "==> Guardian fleet is ready: $URL"
