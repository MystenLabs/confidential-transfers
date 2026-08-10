#!/bin/sh
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# EIF entrypoint: the enclave has no TCP network, so socat exposes the guardian's
# localhost listener on VSOCK:3000 for the parent's TCP<->VSOCK bridge.
set -e
GUARDIAN_LISTEN_ADDR=127.0.0.1:3000 /usr/local/bin/contra-guardian-enclave &
exec socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:127.0.0.1:3000
