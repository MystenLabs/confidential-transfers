#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Enable this Guardian as the token's external authority. The issuer should run
# this only after bootstrap.sh succeeds and an approval smoke test passes.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env GUARDIAN_PACKAGE_ID GUARDIAN_ID CONFIDENTIAL_TOKEN_ID MANAGEMENT_CAP_ID TOKEN_TYPE
require_commands sui

echo "==> enabling Guardian $GUARDIAN_ID for $TOKEN_TYPE"
sui client call \
    --package "$GUARDIAN_PACKAGE_ID" \
    --module guardian \
    --function set_authority \
    --type-args "$TOKEN_TYPE" \
    --args "$CONFIDENTIAL_TOKEN_ID" "$GUARDIAN_ID" "$MANAGEMENT_CAP_ID" \
    --gas-budget "$SUI_GAS_BUDGET" >/dev/null
echo "==> Guardian enabled"
