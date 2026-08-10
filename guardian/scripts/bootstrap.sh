#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the first guardian instance: set the policy (issuer), start an enclave,
# register its key (operator), and mark it ready.
#
#   PACKAGE_ID=0x.. TOKEN_ID=0x.. TOKEN_TYPE=0x..::c::C CAP_ID=0x.. ./bootstrap.sh
#
# The active sui address must hold CAP_ID and be the operator the policy names.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env PACKAGE_ID TOKEN_ID TOKEN_TYPE CAP_ID

OPERATOR="${OPERATOR:-$(sui client active-address)}"
# The policy's url is the fleet's public endpoint, i.e. the proxy (scripts/proxy.sh).
URL="${URL:-http://127.0.0.1:8080}"
# Dev PCRs: nothing verifies them without attestation, so these are placeholders; in
# production they come from `nitro-cli describe-eif` on the built image.
PCR0="${PCR0:-0x00}"
PCR1="${PCR1:-0x01}"
PCR2="${PCR2:-0x02}"

if [ -n "$(list_instances)" ]; then
    echo "error: fleet already bootstrapped ($STATE_DIR is not empty); use scale.sh" >&2
    exit 1
fi

echo "==> setting guardian policy (operator $OPERATOR, url $URL)"
# `Pcrs` is a struct, so it cannot be a pure input: build it in the PTB first.
sui client ptb \
    --move-call "$PACKAGE_ID::guardian::new_pcrs" "vector[$PCR0]" "vector[$PCR1]" "vector[$PCR2]" \
    --assign pcrs \
    --move-call "$PACKAGE_ID::contra::set_guardian_policy" "<$TOKEN_TYPE>" \
        @"$TOKEN_ID" @"$CAP_ID" pcrs @"$OPERATOR" "'$URL'" \
    --gas-budget 100000000 > /dev/null

port=$(next_port)
start_instance "$port"
register_instance "$port"

echo
echo "fleet bootstrapped: 1 instance on :$port"
echo "next: ./scale.sh <n> to add more, ./remove.sh <port> to evict one"
