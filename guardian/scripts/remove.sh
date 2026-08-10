#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Evict an instance: remove its key on chain, then stop the process.
#
#   PACKAGE_ID=0x.. TOKEN_ID=0x.. TOKEN_TYPE=0x..::c::C ./remove.sh 3001
#
# Chain first: a key removed on chain can no longer approve anything, while a stopped
# process whose key is still registered is merely stale. The active sui address must
# be the policy's operator.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env PACKAGE_ID TOKEN_ID TOKEN_TYPE

PORT="${1:-}"
if [ -z "$PORT" ] || [ ! -f "$STATE_DIR/$PORT.env" ]; then
    echo "usage: ./remove.sh <port>   (running: $(list_instances | tr '\n' ' '))" >&2
    exit 1
fi
# shellcheck source=/dev/null  # written by start_instance: PORT, SIGNING_PK, ENC_PK
source "$STATE_DIR/$PORT.env"

# shellcheck disable=SC2153  # SIGNING_PK comes from the sourced state file
echo "==> removing $SIGNING_PK on chain"
sui client call --package "$PACKAGE_ID" --module contra \
    --function remove_guardian_enclave --type-args "$TOKEN_TYPE" \
    --args "$TOKEN_ID" "$SIGNING_PK" \
    --gas-budget 100000000 > /dev/null

if [ -f "$STATE_DIR/$PORT.pid" ]; then
    kill "$(cat "$STATE_DIR/$PORT.pid")" 2>/dev/null || true
    rm -f "$STATE_DIR/$PORT.pid"
fi
rm -f "$STATE_DIR/$PORT.env"
echo "==> :$PORT removed"
echo "fleet: $(list_instances | tr '\n' ' ')"
