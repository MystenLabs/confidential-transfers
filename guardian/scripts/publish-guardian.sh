#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Publish the Guardian Move package. The package lock must already bind its
# `contra` dependency to the intended on-chain Contra package.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_commands jq sui

PACKAGE_PATH=${1:-}
BUILD_ENV=${2:-}
if [ -z "$PACKAGE_PATH" ] || [ ! -f "$PACKAGE_PATH/Move.toml" ]; then
    echo "usage: $0 <guardian-move-package-path> [build-environment]" >&2
    exit 1
fi

ARGS=(--warnings-are-errors --gas-budget "$SUI_GAS_BUDGET" --json)
if [ -n "$BUILD_ENV" ]; then
    ARGS+=(--build-env "$BUILD_ENV")
fi

echo "==> publishing Guardian Move package"
RESULT=$(sui client publish "${ARGS[@]}" "$PACKAGE_PATH")
PACKAGE_ID=$(jq -er \
    '[.objectChanges[]? | select(.type == "published") | .packageId][0]
        // error("Guardian package ID not found in publish result")' \
    <<<"$RESULT")
echo "==> Guardian package published"
echo "export GUARDIAN_PACKAGE_ID=$PACKAGE_ID"
