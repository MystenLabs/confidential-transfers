#!/bin/bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Compiles the canonical bu_token Move package (with contra bundled as
# unpublished) into bytecodes for browser-based publishing. Uses a temporary
# "fresh" environment so contra is NOT resolved to its published devnet
# address.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"
CONTRA_TOML="$REPO_ROOT/move/Move.toml"
BU_TOKEN_DIR="$REPO_ROOT/utils/move/test_token"
BU_TOKEN_TOML="$BU_TOKEN_DIR/Move.toml"
OUTPUT="$APP_DIR/public/bu_token_bytecodes.json"

# Save originals
cp "$CONTRA_TOML" "$CONTRA_TOML.bak"
cp "$BU_TOKEN_TOML" "$BU_TOKEN_TOML.bak"

# Use a "fresh" environment so contra is bundled as unpublished
cat > "$CONTRA_TOML" << 'TOML'
[package]
name = "contra"
edition = "2024"

[environments]
fresh = "00000001"
TOML

cat > "$BU_TOKEN_TOML" << 'TOML'
[package]
name = "bu_token"
edition = "2024"

[dependencies]
contra = { local = "../../../move" }

[environments]
fresh = "00000001"
TOML

rm -f "$BU_TOKEN_DIR/Move.lock"

# Compile. `--no-tree-shaking` keeps the build offline (skips RPC calls the
# tree-shaker would otherwise make against the "fresh" chain id, which has
# no registry and returns "no healthy upstream").
sui move build \
  --dump-bytecode-as-base64 \
  --path "$BU_TOKEN_DIR" \
  -e fresh \
  --with-unpublished-dependencies \
  --no-tree-shaking \
  2>/dev/null > "$OUTPUT"

# Restore originals
mv "$CONTRA_TOML.bak" "$CONTRA_TOML"
mv "$BU_TOKEN_TOML.bak" "$BU_TOKEN_TOML"

MODULE_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT'))['modules']))")
echo "Compiled $MODULE_COUNT modules -> $OUTPUT"
