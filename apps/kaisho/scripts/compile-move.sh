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
BU_TOKEN_LOCK="$BU_TOKEN_DIR/Move.lock"
OUTPUT="$APP_DIR/public/bu_token_bytecodes.json"

# Save the files this script rewrites, and restore them however it exits. The lock has to be saved
# too: it is deleted below to force re-resolution, and the build then writes one pinned to the
# throwaway "fresh" environment, which must not be left in the tree. Restoring from a trap rather
# than at the end also covers a failed build, which would otherwise leave the fabricated manifests
# behind.
cp "$CONTRA_TOML" "$CONTRA_TOML.bak"
cp "$BU_TOKEN_TOML" "$BU_TOKEN_TOML.bak"
cp "$BU_TOKEN_LOCK" "$BU_TOKEN_LOCK.bak"

restore() {
  [ -f "$CONTRA_TOML.bak" ] && mv -f "$CONTRA_TOML.bak" "$CONTRA_TOML"
  [ -f "$BU_TOKEN_TOML.bak" ] && mv -f "$BU_TOKEN_TOML.bak" "$BU_TOKEN_TOML"
  [ -f "$BU_TOKEN_LOCK.bak" ] && mv -f "$BU_TOKEN_LOCK.bak" "$BU_TOKEN_LOCK"
  return 0
}
trap restore EXIT

# Use a "fresh" environment so contra is bundled as unpublished. The system-package pins mirror
# move/Move.toml: the protocol snapshot the toolchain resolves predates
# `rangeproofs::verify_bulletproofs_with_dst_ristretto255`, so pin the framework to the devnet
# release rev that has it. Remove once the snapshot for the live protocol includes the function.
cat > "$CONTRA_TOML" << 'TOML'
[package]
name = "contra"
edition = "2024"
implicit-dependencies = false

[dependencies]
std = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/move-stdlib", rev = "d034d564f84b901efe507ff8f6e4b5c8c0cb53bd" }
sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "d034d564f84b901efe507ff8f6e4b5c8c0cb53bd" }

[environments]
fresh = "00000001"
TOML

cat > "$BU_TOKEN_TOML" << 'TOML'
[package]
name = "bu_token"
edition = "2024"
implicit-dependencies = false

[dependencies]
contra = { local = "../../../move" }
std = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/move-stdlib", rev = "d034d564f84b901efe507ff8f6e4b5c8c0cb53bd" }
sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "d034d564f84b901efe507ff8f6e4b5c8c0cb53bd" }

[environments]
fresh = "00000001"
TOML

rm -f "$BU_TOKEN_LOCK"

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

MODULE_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT'))['modules']))")
echo "Compiled $MODULE_COUNT modules -> $OUTPUT"
