#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Disable the token's external authority requirement. Protected operations then
# use Contra's standard proof verification without a Guardian approval.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env CONTRA_PACKAGE_ID CONFIDENTIAL_TOKEN_ID MANAGEMENT_CAP_ID TOKEN_TYPE
require_commands sui

echo "==> disabling external authority checks for $TOKEN_TYPE"
sui client call \
    --package "$CONTRA_PACKAGE_ID" \
    --module contra \
    --function unset_authority_ref \
    --type-args "$TOKEN_TYPE" \
    --args "$CONFIDENTIAL_TOKEN_ID" "$MANAGEMENT_CAP_ID" \
    --gas-budget "$SUI_GAS_BUDGET" >/dev/null
echo "==> Guardian disabled"
