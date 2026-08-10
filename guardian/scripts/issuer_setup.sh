#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Issuer setup against the active sui env (expects a localnet): publish contra +
# the BU test token, register BU as a confidential token, and write the IDs the
# fleet scripts need to guardian/.fleet/issuer.env.
#
#   ./issuer_setup.sh          # then: source ../.fleet/issuer.env && ./bootstrap.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="${STATE_DIR:-$ROOT/guardian/.fleet}"
mkdir -p "$STATE_DIR"

# `test-publish` with a per-run pubfile: an ephemeral localnet publication that leaves
# the committed `Published.toml` (the real devnet record) untouched. Both packages share
# the pubfile so the BU package resolves its contra dependency from it.
PUBFILE="$STATE_DIR/localnet-pub.toml"
rm -f "$PUBFILE"
echo "==> publishing contra (move/)"
CONTRA_OUT=$(sui client test-publish "$ROOT/move" --build-env devnet --pubfile-path "$PUBFILE" --json)
CONTRA_PKG=$(echo "$CONTRA_OUT" | jq -r '.objectChanges[] | select(.type == "published") | .packageId')
TOKEN_REGISTRY=$(echo "$CONTRA_OUT" | jq -r '.objectChanges[] | select(.objectType? // "" | endswith("::contra::TokenRegistry")) | .objectId')
ACCOUNT_REGISTRY=$(echo "$CONTRA_OUT" | jq -r '.objectChanges[] | select(.objectType? // "" | endswith("::contra::AccountRegistry")) | .objectId')

echo "==> publishing BU test token (utils/move/test_token/)"
BU_OUT=$(sui client test-publish "$ROOT/utils/move/test_token" --build-env devnet --pubfile-path "$PUBFILE" --json)
BU_PKG=$(echo "$BU_OUT" | jq -r '.objectChanges[] | select(.type == "published") | .packageId')
BU_TREASURY=$(echo "$BU_OUT" | jq -r '.objectChanges[] | select(.objectType? // "" | endswith("::bu::BuTreasury")) | .objectId')

echo "==> registering BU as a confidential token"
# `vector<Element<G>>` cannot be a pure arg: build the (empty) auditor list on chain.
REG_OUT=$(sui client ptb \
    --move-call "$CONTRA_PKG::decode::g_vector" "vector[]" \
    --assign auditors \
    --move-call "$BU_PKG::bu::register_confidential" \
        @"$BU_TREASURY" @"$TOKEN_REGISTRY" auditors \
    --gas-budget 100000000 --json)
TOKEN_ID=$(echo "$REG_OUT" | jq -r '.objectChanges[] | select(.objectType? // "" | contains("::contra::ConfidentialToken<")) | .objectId')
CAP_ID=$(echo "$REG_OUT" | jq -r '.objectChanges[] | select(.objectType? // "" | contains("::contra::ManagementCap<")) | .objectId')

cat > "$STATE_DIR/issuer.env" <<ENV
export PACKAGE_ID=$CONTRA_PKG
export TOKEN_ID=$TOKEN_ID
export TOKEN_TYPE=$BU_PKG::bu::BU
export CAP_ID=$CAP_ID
export TOKEN_REGISTRY=$TOKEN_REGISTRY
export ACCOUNT_REGISTRY=$ACCOUNT_REGISTRY
export BU_TREASURY=$BU_TREASURY
ENV
echo
echo "issuer setup complete; IDs in $STATE_DIR/issuer.env:"
cat "$STATE_DIR/issuer.env"
