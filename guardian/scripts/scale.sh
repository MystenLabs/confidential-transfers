#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Add N instances to a bootstrapped fleet. Each generates its own keys, registers
# them, and joins once ready — the issuer is not involved.
#
#   PACKAGE_ID=0x.. TOKEN_ID=0x.. TOKEN_TYPE=0x..::c::C ./scale.sh 2
#
# The active sui address must be the policy's operator.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env PACKAGE_ID TOKEN_ID TOKEN_TYPE

COUNT="${1:-1}"
if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [ "$COUNT" -lt 1 ]; then
    echo "usage: ./scale.sh <count>" >&2
    exit 1
fi

# The policy caps the fleet at MAX_GUARDIAN_ENCLAVE_KEYS.
existing=$(list_instances | wc -l | tr -d ' ')
if [ $((existing + COUNT)) -gt 10 ]; then
    echo "error: $existing running + $COUNT requested exceeds the 10-key policy cap" >&2
    exit 1
fi

for _ in $(seq 1 "$COUNT"); do
    port=$(next_port)
    start_instance "$port"
    register_instance "$port"
done

echo
echo "fleet: $(list_instances | tr '\n' ' ')"
