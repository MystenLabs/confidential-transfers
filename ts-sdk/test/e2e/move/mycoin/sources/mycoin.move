// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Minimal test coin for e2e tests. TreasuryCap and DenyCap are transferred
/// to the publisher so they can mint freely and manage the deny list. The
/// coin is regulated (with global-pause support) so e2e tests can exercise
/// the deny-list and global-pause flows.
module mycoin::mycoin;

use sui::coin_registry;

public struct MYCOIN has drop {}

fun init(witness: MYCOIN, ctx: &mut TxContext) {
    let (mut initializer, treasury_cap) = coin_registry::new_currency_with_otw(
        witness,
        9,
        b"MYCOIN".to_string(),
        b"My Coin".to_string(),
        b"Test coin".to_string(),
        b"".to_string(),
        ctx,
    );
    let deny_cap = initializer.make_regulated(true, ctx);
    initializer.finalize_and_delete_metadata_cap(ctx);
    transfer::public_transfer(treasury_cap, ctx.sender());
    transfer::public_transfer(deny_cap, ctx.sender());
}
