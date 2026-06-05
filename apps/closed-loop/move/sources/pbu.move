// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// pBU — a "pooled BU" token that is swappable 1:1 with BU. A shared `Pool`
/// object custodies the deposited BU and owns the pBU `TreasuryCap`, so
/// anyone can convert BU <-> pBU without trusting a specific admin.
///
/// The supply invariant: `pool.bu_balance.value() == total pBU in circulation`.
module closed_loop::pbu;

use bu_token::bu::BU;
use sui::{balance::{Self, Balance}, coin::{Self, Coin, TreasuryCap}, coin_registry};

/// One-time witness for the pBU coin type.
public struct PBU has drop {}

/// Shared swap pool. Holds BU deposited in exchange for pBU and owns the pBU
/// TreasuryCap so pBU can be minted/burned on demand.
public struct Pool has key {
    id: UID,
    bu_balance: Balance<BU>,
    pbu_treasury: TreasuryCap<PBU>,
}

/// Capability held by the pBU issuer/deployer. Used to authorize privileged
/// setup actions (e.g. initializing the confidential variant of pBU).
public struct PbuAdminCap has key, store { id: UID }

fun init(witness: PBU, ctx: &mut TxContext) {
    let (initializer, treasury_cap) = coin_registry::new_currency_with_otw(
        witness,
        9,
        b"pBU".to_string(),
        b"pBU".to_string(),
        b"Pooled BU".to_string(),
        b"".to_string(),
        ctx,
    );
    initializer.finalize_and_delete_metadata_cap(ctx);
    transfer::share_object(Pool {
        id: object::new(ctx),
        bu_balance: balance::zero<BU>(),
        pbu_treasury: treasury_cap,
    });
    transfer::public_transfer(PbuAdminCap { id: object::new(ctx) }, ctx.sender());
}

/// Deposit `bu` into the pool and receive an equal-value `Coin<PBU>`.
public fun bu_to_pbu(pool: &mut Pool, bu: Coin<BU>, ctx: &mut TxContext): Coin<PBU> {
    let amount = bu.value();
    pool.bu_balance.join(bu.into_balance());
    coin::mint(&mut pool.pbu_treasury, amount, ctx)
}

/// Burn `pbu` and withdraw an equal-value `Coin<BU>` from the pool.
public fun pbu_to_bu(pool: &mut Pool, pbu: Coin<PBU>, ctx: &mut TxContext): Coin<BU> {
    let amount = coin::burn(&mut pool.pbu_treasury, pbu);
    coin::from_balance(pool.bu_balance.split(amount), ctx)
}

/// Expose the pBU `TreasuryCap` to other modules in this package. Needed by
/// `confidential_pbu` to authorize confidential-token setup and policy ops.
public(package) fun treasury_mut(pool: &mut Pool): &mut TreasuryCap<PBU> {
    &mut pool.pbu_treasury
}

// === Test helpers ===

#[test_only]
public fun init_for_testing(ctx: &mut TxContext): PbuAdminCap {
    let cap = coin::create_treasury_cap_for_testing<PBU>(ctx);
    transfer::share_object(Pool {
        id: object::new(ctx),
        bu_balance: balance::zero<BU>(),
        pbu_treasury: cap,
    });
    PbuAdminCap { id: object::new(ctx) }
}
