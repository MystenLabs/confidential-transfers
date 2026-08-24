#!/bin/sh
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set lo up
GUARDIAN_LISTEN_ADDR=127.0.0.1:3000 /usr/local/bin/contra-guardian-enclave &
exec socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:127.0.0.1:3000
