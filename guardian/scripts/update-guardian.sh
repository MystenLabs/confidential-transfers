#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Update PCRs, minimum accepted version, and operator. Changing PCRs increments
# the Guardian version; raising min-version prunes keys registered before it.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env GUARDIAN_PACKAGE_ID GUARDIAN_ID MANAGEMENT_CAP_ID TOKEN_TYPE
require_commands sui

PCR0=${1:-}
PCR1=${2:-}
PCR2=${3:-}
MIN_VERSION=${4:-}
OPERATOR=${5:-}
if [ -z "$OPERATOR" ]; then
    echo "usage: $0 <pcr0-hex> <pcr1-hex> <pcr2-hex> <min-version> <operator-address>" >&2
    exit 1
fi
require_u16 min-version "$MIN_VERSION"
PCR0_LITERAL=$(hex_vector_literal pcr0 "$PCR0")
PCR1_LITERAL=$(hex_vector_literal pcr1 "$PCR1")
PCR2_LITERAL=$(hex_vector_literal pcr2 "$PCR2")

echo "==> updating Guardian $GUARDIAN_ID"
sui client ptb \
    --move-call "$GUARDIAN_PACKAGE_ID::guardian::new_pcrs" \
        "$PCR0_LITERAL" "$PCR1_LITERAL" "$PCR2_LITERAL" \
    --assign pcrs \
    --move-call "$GUARDIAN_PACKAGE_ID::guardian::update" "<$TOKEN_TYPE>" \
        @"$GUARDIAN_ID" @"$MANAGEMENT_CAP_ID" pcrs "$MIN_VERSION" @"$OPERATOR" \
    --gas-budget "$SUI_GAS_BUDGET" >/dev/null
echo "==> Guardian updated"
