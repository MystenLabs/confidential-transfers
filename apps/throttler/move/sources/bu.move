// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// BU — a regulated test token for the throttler example. The `TreasuryCap`,
/// `DenyCap`, and `ThrottlerAdminCap` are all transferred to the deployer at
/// `init`: minting and deny-list management are issuer-owned, and the same
/// deployer authorizes setup of the confidential variant.
module throttler::bu;

use sui::coin_registry;

#[test_only]
use sui::coin::{Self, TreasuryCap};

/// One-time witness for the BU coin type.
public struct BU has drop {}

/// Capability held by the BU issuer/deployer. Used to authorize admin
/// operations on the `ThrottledPool` (`set_min_duration`, `set_pending`).
public struct ThrottlerAdminCap has key, store { id: UID }

fun init(witness: BU, ctx: &mut TxContext) {
    let (mut initializer, treasury_cap) = coin_registry::new_currency_with_otw(
        witness,
        9,
        b"BU".to_string(),
        b"BU".to_string(),
        b"Throttler BU".to_string(),
        b"".to_string(),
        ctx,
    );
    let deny_cap = initializer.make_regulated(true, ctx);
    initializer.finalize_and_delete_metadata_cap(ctx);
    transfer::public_transfer(treasury_cap, ctx.sender());
    transfer::public_transfer(deny_cap, ctx.sender());
    transfer::public_transfer(ThrottlerAdminCap { id: object::new(ctx) }, ctx.sender());
}

// === Test helpers ===

#[test_only]
public fun init_for_testing(ctx: &mut TxContext): (TreasuryCap<BU>, ThrottlerAdminCap) {
    (coin::create_treasury_cap_for_testing<BU>(ctx), ThrottlerAdminCap { id: object::new(ctx) })
}
