#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Shared config for the guardian fleet scripts. Source, don't run.
#
# Required:
#   PACKAGE_ID   published contra package
#   TOKEN_ID     the ConfidentialToken<T> object
#   TOKEN_TYPE   its type argument, e.g. 0xabc::my_coin::MY_COIN
# Optional:
#   CAP_ID       ManagementCap<T>, only for `bootstrap` when setting the policy
#   STATE_DIR    where instance state is kept (default guardian/.fleet)
#   BASE_PORT    first instance port (default 3001)

set -euo pipefail

STATE_DIR="${STATE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.fleet}"
BASE_PORT="${BASE_PORT:-3001}"
ENCLAVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../enclave" && pwd)"
mkdir -p "$STATE_DIR"

require_env() {
    for var in "$@"; do
        if [ -z "${!var:-}" ]; then
            echo "error: $var is not set (see guardian/scripts/common.sh)" >&2
            exit 1
        fi
    done
}

# Next free port at or above BASE_PORT that has no state file.
next_port() {
    local port=$BASE_PORT
    while [ -f "$STATE_DIR/$port.env" ]; do port=$((port + 1)); done
    echo "$port"
}

# Start a dev enclave on $1 and wait for it to answer, which is NOT a real enclave, so
# registration uses the dev path below.
start_instance() {
    local port=$1
    echo "==> starting enclave on :$port"
    (cd "$ENCLAVE_DIR" && GUARDIAN_LISTEN_ADDR="127.0.0.1:$port" \
        cargo run --quiet --no-default-features --features non-enclave-dev \
        > "$STATE_DIR/$port.log" 2>&1 &
     echo $! > "$STATE_DIR/$port.pid")
    for _ in $(seq 1 60); do
        # /registered is 503 until registered; any answer means the server is up.
        if curl -fsS -o /dev/null "http://127.0.0.1:$port/attestation" 2>/dev/null; then return 0; fi
        sleep 1
    done
    echo "error: enclave on :$port did not come up; see $STATE_DIR/$port.log" >&2
    exit 1
}

# Register the instance via the shared register.sh (dev path) and record its keys.
register_instance() {
    local port=$1
    local keys
    keys=$(HOST="127.0.0.1:$port" "$(dirname "${BASH_SOURCE[0]}")/register.sh")
    cat > "$STATE_DIR/$port.env" <<STATE
PORT=$port
$keys
STATE
}

# Instance state files are `<port>.env`; issuer.env and the pubfile are not instances.
list_instances() {
    local f port
    for f in "$STATE_DIR"/*.env; do
        port=$(basename "$f" .env)
        if [[ $port =~ ^[0-9]+$ ]]; then echo "$port"; fi
    done
}
