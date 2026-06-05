#!/bin/bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Vercel build script for the kaisho app.
#
# Vercel's build image doesn't ship with Rust, so we install rustup
# (with the wasm32 target) and wasm-pack before building the
# @contra/bulletproofs-wasm bindings. Everything after that is the standard
# pnpm flow.

set -euxo pipefail

# fastcrypto pulls in blst and libsecp256k1, whose build scripts use
# cc-rs to compile C for wasm32-unknown-unknown. cc-rs requires clang
# for that target; Vercel's Amazon Linux 2023 image ships only gcc.
# Builds run as root, so dnf works without sudo.
dnf install -y clang

# Non-interactive rustup install with the wasm32 target. Using
# --no-modify-path because we export PATH manually below (more robust
# than sourcing $HOME/.cargo/env, which isn't created in some build
# environments).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --no-modify-path --profile minimal \
              --default-toolchain stable \
              --target wasm32-unknown-unknown

export PATH="$HOME/.cargo/bin:$PATH"
cargo --version
rustup target list --installed

# Prebuilt wasm-pack binary (installer drops it into $HOME/.cargo/bin).
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
wasm-pack --version

# Build the WASM package first so its nodejs/web outputs exist before ts-sdk
# installs it as a `file:` dep (pnpm only packs what's present at install time).
cd ../../utils/bulletproofs-wasm
pnpm build:wasm

# Build order matters: contra-utils now imports types from ts-sdk for its
# setup helpers, while ts-sdk's e2e tests import from contra-utils. ts-sdk's
# `src/` does not touch contra-utils (only `test/` does), so we can build
# ts-sdk first against an empty contra-utils symlink, then build contra-utils
# against ts-sdk's dist, then build kaisho.
cd ../../ts-sdk
pnpm install
pnpm build

cd ../utils/ts-utils
pnpm install
pnpm build

cd ../../apps/kaisho
# --force ensures contra-utils' freshly-built dist is re-packed into
# kaisho's virtual store; without it, pnpm only packs what existed in
# `files` at first-install time.
pnpm install --force
pnpm run build
