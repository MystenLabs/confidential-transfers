#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Register one guardian instance: fetch its /attestation, register the key onchain,
# then POST /registered to open the proxy's readiness gate. Used by the local fleet
# (common.sh) and by sui-operations operators against a deployed instance's :3000
# (directly in-VPC, or via an SSM port-forward).
#
#   PACKAGE_ID=.. TOKEN_ID=.. TOKEN_TYPE=.. [HOST=127.0.0.1:3000] ./register.sh
#
# The mode is detected from the document: a dev (non-enclave-dev) build serves the
# raw 64-byte user_data, registered via `register_guardian_enclave_for_dev`; a real
# enclave serves a signed document, loaded with `0x2::nitro_attestation` and
# registered via `register_guardian_enclave`. MODE=dev|attested overrides.
# In dev mode the keys are echoed as shell assignments for callers to eval.
set -euo pipefail

HOST="${HOST:-127.0.0.1:3000}"
: "${PACKAGE_ID:?}" "${TOKEN_ID:?}" "${TOKEN_TYPE:?}"

doc_hex=$(curl -fsS "http://$HOST/attestation" | jq -r .attestation | base64 -d | xxd -p | tr -d '\n')
MODE="${MODE:-$([ "${#doc_hex}" -eq 128 ] && echo dev || echo attested)}"

if [ "$MODE" = dev ]; then
    # The dev document is the bare user_data: 32 bytes of signing_pk then 32 of enc_pk.
    signing_pk=${doc_hex:0:64}
    enc_pk=${doc_hex:64:64}
    echo "==> dev-registering $HOST (signing_pk 0x${signing_pk:0:16}...)" >&2
    sui client call --package "$PACKAGE_ID" --module contra \
        --function register_guardian_enclave_for_dev --type-args "$TOKEN_TYPE" \
        --args "$TOKEN_ID" "0x$signing_pk" "0x$enc_pk" \
        --gas-budget 100000000 > /dev/null
    echo "SIGNING_PK=0x$signing_pk"
    echo "ENC_PK=0x$enc_pk"
else
    echo "==> registering $HOST's attestation document (${#doc_hex} hex chars)" >&2
    # `register_guardian_enclave` takes a NitroAttestationDocument, which only
    # `0x2::nitro_attestation::load_nitro_attestation` (bytes + Clock) can build.
    # shellcheck disable=SC2001  # bash replacement cannot reference the matched pair
    doc_bytes=$(sed -E 's/(..)/0x\1u8,/g' <<<"$doc_hex")
    doc_literal="vector[${doc_bytes%,}]"
    sui client ptb \
        --move-call 0x2::nitro_attestation::load_nitro_attestation "$doc_literal" @0x6 \
        --assign doc \
        --move-call "$PACKAGE_ID::contra::register_guardian_enclave" "<$TOKEN_TYPE>" \
            @"$TOKEN_ID" doc \
        --gas-budget 100000000 > /dev/null
fi

curl -fsS -X POST "http://$HOST/registered" > /dev/null
echo "==> $HOST registered and ready" >&2
