// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Shared on-chain record of the object IDs created during token deployment.
/// Used by the dapp to query the single `TokenConfig` object to discover
/// every ID it needs to interact with.
///
/// Used for the demo wallet. In future releases, all IDs will be static and
/// hardcoded per network.
module bu_token::token_config;

/// Stores the object IDs produced by the in-app issuer setup deployment.
/// `binary_digest` is the digest of the published Move package bytes (as
/// reported by `sui move build`); the dapp uses it to detect configs that
/// were created from a stale build.
public struct TokenConfig has key, store {
    id: UID,
    bu_package: address,
    bu_treasury: address,
    contra_package: address,
    token_registry: address,
    account_registry: address,
    binary_digest: vector<u8>,
}

/// Create a shared `TokenConfig` object containing the given IDs.
public fun create(
    bu_package: address,
    bu_treasury: address,
    contra_package: address,
    token_registry: address,
    account_registry: address,
    binary_digest: vector<u8>,
    ctx: &mut TxContext,
) {
    transfer::share_object(TokenConfig {
        id: object::new(ctx),
        bu_package,
        bu_treasury,
        contra_package,
        token_registry,
        account_registry,
        binary_digest,
    });
}
