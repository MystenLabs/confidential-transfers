#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Create and share a Guardian<T>. This does not enable it for Contra; run
# enable-guardian.sh only after the operator fleet is registered and healthy.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env GUARDIAN_PACKAGE_ID MANAGEMENT_CAP_ID TOKEN_TYPE
require_commands jq
require_guardian_cli

PCR0=${1:-}
PCR1=${2:-}
PCR2=${3:-}
OPERATOR=${4:-}
if [ -z "$OPERATOR" ]; then
    echo "usage: $0 <pcr0-hex> <pcr1-hex> <pcr2-hex> <operator-address>" >&2
    exit 1
fi
echo "==> creating Guardian<$TOKEN_TYPE> for operator $OPERATOR"
RESULT=$(guardian_cli create \
    --guardian-package "$GUARDIAN_PACKAGE_ID" \
    --management-cap "$MANAGEMENT_CAP_ID" \
    --token-type "$TOKEN_TYPE" \
    --pcr0 "$PCR0" --pcr1 "$PCR1" --pcr2 "$PCR2" \
    --operator "$OPERATOR")
GUARDIAN_ID=$(jq -er '.guardian_id' <<<"$RESULT")
echo "==> Guardian created but not enabled"
echo "export GUARDIAN_ID=$GUARDIAN_ID"
