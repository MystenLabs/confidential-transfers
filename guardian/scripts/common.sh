#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Shared configuration and AWS/Pulumi helpers for Guardian fleet operations.
# Source this file from another script; do not execute it directly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SUI_OPERATIONS_DIR="${SUI_OPERATIONS_DIR:-$(cd "$REPO_ROOT/.." && pwd)/sui-operations}"
ENCLAVE_SERVICE_DIR="$SUI_OPERATIONS_DIR/pulumi/services/contra-guardian-enclave"
PROXY_SERVICE_DIR="$SUI_OPERATIONS_DIR/pulumi/services/contra-guardian-proxy"
PULUMI_STACK="${PULUMI_STACK:-devnet}"
PULUMI_ORG="${PULUMI_ORG:-mysten}"
PULUMI_STACK_REF="$PULUMI_ORG/$PULUMI_STACK"
AWS_REGION="${AWS_REGION:-us-west-2}"
MAX_ENCLAVE_KEYS=16
SUI_GAS_BUDGET="${SUI_GAS_BUDGET:-100000000}"

guardian_cli() {
    local args=(--gas-budget "$SUI_GAS_BUDGET")
    if [ -n "${SUI_WALLET:-}" ]; then
        args+=(--wallet "$SUI_WALLET")
    fi
    if [ -n "${SUI_ACTIVE_ADDRESS:-}" ]; then
        args+=(--active-address "$SUI_ACTIVE_ADDRESS")
    fi
    if [ -n "${SUI_RPC_URL:-}" ]; then
        args+=(--rpc-url "$SUI_RPC_URL")
    fi

    if [ -n "${GUARDIAN_CLI:-}" ]; then
        "$GUARDIAN_CLI" "${args[@]}" "$@"
    else
        cargo run --quiet --manifest-path "$REPO_ROOT/Cargo.toml" \
            -p contra-guardian-cli -- "${args[@]}" "$@"
    fi
}

require_guardian_cli() {
    if [ -n "${GUARDIAN_CLI:-}" ]; then
        if [ ! -x "$GUARDIAN_CLI" ]; then
            echo "error: GUARDIAN_CLI is not executable: $GUARDIAN_CLI" >&2
            exit 1
        fi
    else
        require_commands cargo
    fi
}

require_env() {
    local name
    for name in "$@"; do
        if [ -z "${!name:-}" ]; then
            echo "error: $name is not set" >&2
            exit 1
        fi
    done
}

require_commands() {
    local command
    for command in "$@"; do
        command -v "$command" >/dev/null || {
            echo "error: required command not found: $command" >&2
            exit 1
        }
    done
}

require_u16() {
    local name=$1
    local value=$2
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -gt 65535 ]; then
        echo "error: $name must be an integer between 0 and 65535" >&2
        exit 1
    fi
}

check_operations_repo() {
    if [ ! -f "$ENCLAVE_SERVICE_DIR/Pulumi.yaml" ] || [ ! -f "$PROXY_SERVICE_DIR/Pulumi.yaml" ]; then
        echo "error: Guardian Pulumi services not found under $SUI_OPERATIONS_DIR" >&2
        echo "set SUI_OPERATIONS_DIR to the sui-operations checkout" >&2
        exit 1
    fi
}

prepare_fleet_operation() {
    require_env GUARDIAN_PACKAGE_ID GUARDIAN_ID TOKEN_TYPE
    require_commands aws jq pulumi
    require_guardian_cli
    check_operations_repo
    ensure_pulumi_stack "$ENCLAVE_SERVICE_DIR"
    ensure_pulumi_stack "$PROXY_SERVICE_DIR"
}

validate_fleet_spec() {
    local count=$1
    local contra_commit=$2
    if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ] || [ "$count" -gt "$MAX_ENCLAVE_KEYS" ] ||
        ! [[ "$contra_commit" =~ ^[0-9a-f]{40}$ ]]; then
        return 1
    fi
}

configure_enclave_fleet() {
    local count=$1
    local contra_commit=$2
    (
        cd "$ENCLAVE_SERVICE_DIR"
        pulumi config set enclave-count "$count" --stack "$PULUMI_STACK_REF"
        pulumi config set contra-commit "$contra_commit" --stack "$PULUMI_STACK_REF"
    )
}

deploy_enclave_fleet() {
    (cd "$ENCLAVE_SERVICE_DIR" && pulumi up --yes --stack "$PULUMI_STACK_REF")
}

register_enclave_fleet() {
    local instance_id
    while IFS= read -r instance_id; do
        "$SCRIPT_DIR/register.sh" "$instance_id"
    done < <(fleet_instance_ids)
}

deploy_guardian_proxy() {
    (cd "$PROXY_SERVICE_DIR" && pulumi up --yes --stack "$PULUMI_STACK_REF")
}

pulumi_output() {
    local service_dir=$1
    local output=$2
    (cd "$service_dir" && pulumi stack output "$output" --stack "$PULUMI_STACK_REF" --json)
}

ensure_pulumi_stack() {
    local service_dir=$1
    (
        cd "$service_dir"
        if ! pulumi stack select "$PULUMI_STACK_REF" >/dev/null 2>&1; then
            pulumi stack init "$PULUMI_STACK_REF"
        fi
    )
}

fleet_instance_ids() {
    pulumi_output "$ENCLAVE_SERVICE_DIR" enclave_instance_ids | jq -er '.[]'
}

wait_for_ssm() {
    local instance_id=$1
    for _ in $(seq 1 60); do
        if aws ssm describe-instance-information \
            --region "$AWS_REGION" \
            --filters "Key=InstanceIds,Values=$instance_id" \
            --query 'InstanceInformationList[0].PingStatus' \
            --output text 2>/dev/null | grep -qx Online; then
            return
        fi
        sleep 5
    done
    echo "error: $instance_id did not become available through SSM" >&2
    exit 1
}

ssm_run() {
    local instance_id=$1
    local remote_command=$2
    local parameters command_id invocation status
    parameters=$(jq -cn --arg command "$remote_command" '{commands: [$command]}')
    command_id=$(aws ssm send-command \
        --region "$AWS_REGION" \
        --instance-ids "$instance_id" \
        --document-name AWS-RunShellScript \
        --parameters "$parameters" \
        --query 'Command.CommandId' \
        --output text)
    aws ssm wait command-executed \
        --region "$AWS_REGION" \
        --command-id "$command_id" \
        --instance-id "$instance_id" || true
    invocation=$(aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$command_id" \
        --instance-id "$instance_id" \
        --output json)
    status=$(jq -r '.Status' <<<"$invocation")
    if [ "$status" != Success ]; then
        jq -r '.StandardErrorContent' <<<"$invocation" >&2
        echo "error: SSM command on $instance_id ended with $status" >&2
        return 1
    fi
    jq -r '.StandardOutputContent' <<<"$invocation"
}

guardian_key_index() {
    local key_index
    key_index=$(aws ec2 describe-tags \
        --region "$AWS_REGION" \
        --filters "Name=resource-id,Values=$1" 'Name=key,Values=GuardianKeyIndex' \
        --query 'Tags[0].Value' \
        --output text)
    printf '%s\n' "${key_index%.0}"
}

remove_guardian_key() {
    local key_index=$1
    guardian_cli remove-enclave \
        --guardian-package "$GUARDIAN_PACKAGE_ID" \
        --guardian "$GUARDIAN_ID" \
        --token-type "$TOKEN_TYPE" \
        --key-index "$key_index" >/dev/null
}
