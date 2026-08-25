#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Update PCRs, minimum accepted version, and operator. Changing PCRs increments
# the Guardian version; raising min-version prunes keys registered before it.

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_env GUARDIAN_PACKAGE_ID GUARDIAN_ID MANAGEMENT_CAP_ID TOKEN_TYPE
require_guardian_cli

PCR0=${1:-}
PCR1=${2:-}
PCR2=${3:-}
MIN_VERSION=${4:-}
OPERATOR=${5:-}
if [ -z "$OPERATOR" ]; then
    echo "usage: $0 <pcr0-hex> <pcr1-hex> <pcr2-hex> <min-version> <operator-address>" >&2
    exit 1
fi
require_u16 min-version "$MIN_VERSION"
echo "==> updating Guardian $GUARDIAN_ID"
guardian_cli update \
    --guardian-package "$GUARDIAN_PACKAGE_ID" \
    --guardian "$GUARDIAN_ID" \
    --management-cap "$MANAGEMENT_CAP_ID" \
    --token-type "$TOKEN_TYPE" \
    --pcr0 "$PCR0" --pcr1 "$PCR1" --pcr2 "$PCR2" \
    --min-version "$MIN_VERSION" \
    --operator "$OPERATOR" >/dev/null
echo "==> Guardian updated"
