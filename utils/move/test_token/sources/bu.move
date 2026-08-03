// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// BU — a test token used by the contra demos. Anyone can mint via `mint_10`
/// or `mint(amount)`; the TreasuryCap lives inside a shared `BuTreasury` so
/// minting is permissionless. Marked as a regulated coin, so the issuer can
/// manage a per-address denylist and a global pause via
/// `sui::coin::deny_list_v2_*` — useful for the demos that exercise contra's
/// freeze hooks. `register_confidential` registers BU as a confidential token
/// with the supplied auditor public key (pass `option::none()` for none) and
/// shares the resulting `ConfidentialToken<BU>`.
module bu_token::bu;

use contra::contra;
use sui::{
    coin::{Self, Coin, TreasuryCap},
    coin_registry,
    event,
    group_ops::Element,
    ristretto255::G
};

/// One-time witness for the BU coin type.
public struct BU has drop {}

/// Shared object holding the TreasuryCap, allowing anyone to mint.
public struct BuTreasury has key {
    id: UID,
    cap: TreasuryCap<BU>,
}

/// Emitted when BU tokens are minted.
public struct MintEvent has copy, drop {
    recipient: address,
    amount: u64,
}

fun init(witness: BU, ctx: &mut TxContext) {
    let (mut initializer, treasury_cap) = coin_registry::new_currency_with_otw(
        witness,
        9,
        b"BU".to_string(),
        b"Bu".to_string(),
        b"Bu token".to_string(),
        b"".to_string(),
        ctx,
    );
    let deny_cap = initializer.make_regulated(true, ctx);
    initializer.finalize_and_delete_metadata_cap(ctx);
    transfer::public_transfer(deny_cap, ctx.sender());
    transfer::share_object(BuTreasury {
        id: object::new(ctx),
        cap: treasury_cap,
    });
}

/// Mint 10 BU (10 * 10^9 base units) and send to the caller. Open to anyone.
public fun mint_10(treasury: &mut BuTreasury, ctx: &mut TxContext) {
    let amount = 10_000_000_000;
    let coin = coin::mint(&mut treasury.cap, amount, ctx);
    transfer::public_transfer(coin, ctx.sender());
    event::emit(MintEvent { recipient: ctx.sender(), amount });
}

/// Mint `amount` base units and return the coin to the caller (so PTBs can
/// chain it directly into `contra::wrap` etc.).
public fun mint(treasury: &mut BuTreasury, amount: u64, ctx: &mut TxContext): Coin<BU> {
    event::emit(MintEvent { recipient: ctx.sender(), amount });
    coin::mint(&mut treasury.cap, amount, ctx)
}

/// Register BU as a confidential token. Shares the `ConfidentialToken<BU>`
/// and transfers `ManagementCap<BU>` to the caller. Pass `option::none()` for
/// `auditor_pk` to register without auditors.
public fun register_confidential(
    treasury: &mut BuTreasury,
    registry: &mut contra::TokenRegistry,
    auditor_pk: Option<Element<G>>,
    ctx: &mut TxContext,
) {
    let (ct, management_cap) = contra::new_confidential_token<BU>(
        registry,
        &mut treasury.cap,
        auditor_pk,
        ctx,
    );
    contra::share_confidential_token(ct);
    transfer::public_transfer(management_cap, ctx.sender());
}

/// Permissionless wrapper around `contra::global_unfreeze`, exposing the
/// TreasuryCap held by the shared `BuTreasury`. Mirrors `mint_10`'s open
/// access so the demos can flip the global freeze off without holding the
/// TreasuryCap directly.
public fun unfreeze_confidential(treasury: &BuTreasury, ct: &mut contra::ConfidentialToken<BU>) {
    contra::global_unfreeze(ct, &treasury.cap);
}

#[test_only]
/// Test-only constructor: bypasses the OTW path so test scenarios can mint
/// without `init`. Shares a fresh `BuTreasury` with a stand-in TreasuryCap.
public fun init_for_testing(ctx: &mut TxContext) {
    let cap = coin::create_treasury_cap_for_testing<BU>(ctx);
    transfer::share_object(BuTreasury { id: object::new(ctx), cap });
}
