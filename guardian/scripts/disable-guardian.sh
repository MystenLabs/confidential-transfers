#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Disable the token's external authority requirement. Protected operations then
# use Contra's standard proof verification without a Guardian approval.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env CONTRA_PACKAGE_ID CONFIDENTIAL_TOKEN_ID MANAGEMENT_CAP_ID TOKEN_TYPE
require_guardian_cli

echo "==> disabling external authority checks for $TOKEN_TYPE"
guardian_cli disable \
    --contra-package "$CONTRA_PACKAGE_ID" \
    --confidential-token "$CONFIDENTIAL_TOKEN_ID" \
    --management-cap "$MANAGEMENT_CAP_ID" \
    --token-type "$TOKEN_TYPE" >/dev/null
echo "==> Guardian disabled"
