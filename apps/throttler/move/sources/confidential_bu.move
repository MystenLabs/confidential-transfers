// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Confidential variant of BU with throttled unwrap.
///
/// `contra::unwrap` is gated by an issuer-installed policy keyed on
/// `BuWitness`, which only this module can mint. Users must call
/// `unwrap` here: the unwrapped coin is parked in the shared
/// `ThrottledPool`'s balance and a `PendingUnwrap { amount, request_time }`
/// entry is appended to a per-address queue stored as a dynamic field on
/// the pool. Once `clock.timestamp_ms() >= request_time + pool.min_duration`,
/// the user may call `take` to receive a `Coin<BU>`.
///
/// The issuer holds `ThrottlerAdminCap` and can adjust `min_duration` or
/// overwrite any per-address queue (`set_pending`). Seizure is performed by
/// clearing the victim's entries and adding a matching entry under the
/// issuer's own address with `request_time: 0`, then calling `take`.
module throttler::confidential_bu;

use contra::{
    contra::{Self, Account, ConfidentialToken, ManagementCap, Pool, TokenRegistry},
    encrypted_amount::EncryptedAmount,
    nizk::{DdhProof, ElGamalProof},
    range_proof::RangeProofs
};
use sui::{
    balance::{Self, Balance},
    clock::Clock,
    coin::{Self, Coin, TreasuryCap},
    deny_list::DenyList,
    dynamic_field as df
};
use throttler::bu::{BU, ThrottlerAdminCap};

// === Errors ===

/// Caller of `unwrap` is not the owner of the supplied `Account`.
const EUnauthorized: u64 = 0;

/// The `Coin<BU>` returned by `contra::unwrap` did not have value equal to
/// the requested `amount`. Defensive check; would indicate a bug in contra.
const EAmountMismatch: u64 = 1;

// === Constants ===

/// Bitmap index for the `unwrap` operation in `contra::contra`. Must stay in
/// sync with `contra::contra::PERMISSIONED_UNWRAP = 2`.
const UNWRAP_OP: u8 = 2;

// === Types ===

/// Witness for the permissioned `unwrap` operation. Only this module can
/// construct it, which is what lets us enforce the time-delay queue here.
public struct BuWitness has drop {}

/// Shared throttler pool. Holds unwrapped `Balance<BU>` until each
/// `PendingUnwrap` matures and is claimed via `take`. Per-address queues are
/// stored as `vector<PendingUnwrap>` dynamic fields keyed by `address`.
public struct ThrottledPool has key {
    id: UID,
    min_duration: u64,
    balance: Balance<BU>,
}

/// A pending unwrap claim: `amount` of BU is releasable once
/// `clock.timestamp_ms() >= request_time + pool.min_duration`.
///
/// Linear (no `copy`, no `drop`): a `PendingUnwrap` is a non-fungible claim
/// ticket on `pool.balance`. Every entry must be created by `unwrap` (which
/// also deposits the matching coin) and destroyed either by `take` (which
/// withdraws the matching coin) or by the issuer-only `set_pending` (which
/// is the seize path).
public struct PendingUnwrap has store {
    amount: u64,
    request_time: u64,
}

// === Setup ===

/// Create the `ConfidentialToken<BU>`, install a policy that makes `unwrap`
/// permissioned with this module's `BuWitness`, share the confidential token,
/// and share a fresh `ThrottledPool`. Returns the `ManagementCap<BU>` to the
/// caller.
///
/// Implicitly gated by ownership of `&mut TreasuryCap<BU>`: only the BU
/// deployer (who received the cap at `init`) can perform setup.
public fun setup(
    treasury_cap: &mut TreasuryCap<BU>,
    registry: &mut TokenRegistry,
    min_duration: u64,
    ctx: &mut TxContext,
): ManagementCap<BU> {
    let (mut ct, management_cap) = contra::new_confidential_token<BU>(
        registry,
        treasury_cap,
        vector[],
        ctx,
    );
    ct.set_policy<BU, BuWitness>(treasury_cap, vector[UNWRAP_OP]);
    contra::share_confidential_token(ct);

    transfer::share_object(ThrottledPool {
        id: object::new(ctx),
        min_duration,
        balance: balance::zero<BU>(),
    });

    management_cap
}

// === Issuer admin ===

/// Update the minimum delay between `unwrap` and a matured `take`. Applies
/// retroactively to all queued entries (the check is against the current
/// `pool.min_duration`).
public fun set_min_duration(_cap: &ThrottlerAdminCap, pool: &mut ThrottledPool, new_duration: u64) {
    pool.min_duration = new_duration;
}

/// Overwrite the pending-unwrap queue at `addr`. Passing an empty vector
/// clears the queue (the dynamic field is removed). Used by the issuer to
/// seize tokens: clear the victim's entries, then add a matching entry under
/// the issuer's own address with `request_time: 0` and claim via `take`.
public fun set_pending(
    _cap: &ThrottlerAdminCap,
    pool: &mut ThrottledPool,
    addr: address,
    entries: vector<PendingUnwrap>,
) {
    if (df::exists(&pool.id, addr)) {
        let existing: vector<PendingUnwrap> = df::remove(&mut pool.id, addr);
        // Explicit destruction: PendingUnwrap is linear, so seizure must
        // visibly burn the old claims. The corresponding BU stays in
        // `pool.balance` and can be reassigned by entries added below.
        existing.do!(|e| {
            let PendingUnwrap { amount: _, request_time: _ } = e;
        });
    };
    if (!entries.is_empty()) {
        df::add(&mut pool.id, addr, entries);
    } else {
        entries.destroy_empty();
    };
}

/// Public constructor for `PendingUnwrap`, used by PTBs that build inputs to
/// `set_pending`.
public fun new_pending(amount: u64, request_time: u64): PendingUnwrap {
    PendingUnwrap { amount, request_time }
}

// === User-facing throttled unwrap ===

/// Throttled unwrap: removes `amount` BU from `account`'s confidential
/// balance via `contra::unwrap`, parks the coin in `pool.balance`, and
/// appends a `PendingUnwrap { amount, request_time: clock.timestamp_ms() }`
/// to the queue at `account.owner()`. The coin becomes claimable via `take`
/// once the entry matures.
public fun unwrap(
    ct: &ConfidentialToken<BU>,
    account: &mut Account,
    deny_list: &DenyList,
    contra_pool: &mut Pool<BU>,
    pool: &mut ThrottledPool,
    new_balance: EncryptedAmount,
    new_balance_consistency_proof: ElGamalProof,
    new_balance_range_proofs: RangeProofs,
    amount: u64,
    balance_proof: &DdhProof,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let owner = account.owner();
    assert!(ctx.sender() == owner, EUnauthorized);
    let auth = ct.authorize_with_witness(UNWRAP_OP, owner, BuWitness {});
    let coin = contra::unwrap<BU>(
        account,
        &auth,
        ct,
        deny_list,
        contra_pool,
        new_balance,
        new_balance_consistency_proof,
        new_balance_range_proofs,
        amount,
        balance_proof,
        option::none(), // No approval authority is configured for this token.
        ctx,
    );
    assert!(coin.value() == amount, EAmountMismatch);
    pool.balance.join(coin.into_balance());

    let entry = PendingUnwrap { amount, request_time: clock.timestamp_ms() };
    if (df::exists(&pool.id, owner)) {
        let queue: &mut vector<PendingUnwrap> = df::borrow_mut(&mut pool.id, owner);
        queue.push_back(entry);
    } else {
        df::add(&mut pool.id, owner, vector[entry]);
    };
}

// === User-facing claim ===

/// Claim all matured pending unwraps for the caller. Returns a `Coin<BU>`
/// for the sum of matured amounts (zero if none). Surviving entries are
/// written back to the queue; an empty queue removes the dynamic field.
public fun take(pool: &mut ThrottledPool, clock: &Clock, ctx: &mut TxContext): Coin<BU> {
    let sender = ctx.sender();
    if (!df::exists(&pool.id, sender)) {
        return coin::zero<BU>(ctx)
    };
    let entries: vector<PendingUnwrap> = df::remove(&mut pool.id, sender);
    let now = clock.timestamp_ms();
    let min_duration = pool.min_duration;
    let mut total: u64 = 0;
    let mut survivors = vector<PendingUnwrap>[];
    entries.do!(|e| {
        if (now >= e.request_time + min_duration) {
            // Matured: destroy the claim ticket; its `amount` is released
            // from `pool.balance` below.
            let PendingUnwrap { amount, request_time: _ } = e;
            total = total + amount;
        } else {
            survivors.push_back(e);
        };
    });
    if (!survivors.is_empty()) {
        df::add(&mut pool.id, sender, survivors);
    } else {
        survivors.destroy_empty();
    };
    coin::from_balance(pool.balance.split(total), ctx)
}
