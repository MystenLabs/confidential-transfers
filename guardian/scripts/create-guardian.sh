#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Create and share a Guardian<T>. This does not enable it for Contra; run
# enable-guardian.sh only after the operator fleet is registered and healthy.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env GUARDIAN_PACKAGE_ID MANAGEMENT_CAP_ID TOKEN_TYPE
require_commands jq sui

PCR0=${1:-}
PCR1=${2:-}
PCR2=${3:-}
OPERATOR=${4:-}
if [ -z "$OPERATOR" ]; then
    echo "usage: $0 <pcr0-hex> <pcr1-hex> <pcr2-hex> <operator-address>" >&2
    exit 1
fi
PCR0_LITERAL=$(hex_vector_literal pcr0 "$PCR0")
PCR1_LITERAL=$(hex_vector_literal pcr1 "$PCR1")
PCR2_LITERAL=$(hex_vector_literal pcr2 "$PCR2")

echo "==> creating Guardian<$TOKEN_TYPE> for operator $OPERATOR"
RESULT=$(sui client ptb \
    --move-call "$GUARDIAN_PACKAGE_ID::guardian::new_pcrs" \
        "$PCR0_LITERAL" "$PCR1_LITERAL" "$PCR2_LITERAL" \
    --assign pcrs \
    --move-call "$GUARDIAN_PACKAGE_ID::guardian::new_guardian" "<$TOKEN_TYPE>" \
        @"$MANAGEMENT_CAP_ID" pcrs @"$OPERATOR" \
    --gas-budget "$SUI_GAS_BUDGET" \
    --json)
GUARDIAN_ID=$(jq -er \
    '[.objectChanges[]? |
        select(.type == "created" and (.objectType | contains("::guardian::Guardian<"))) |
        .objectId][0] // error("Guardian object ID not found in transaction result")' \
    <<<"$RESULT")
echo "==> Guardian created but not enabled"
echo "export GUARDIAN_ID=$GUARDIAN_ID"
