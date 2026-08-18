// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Confidential value: `EncryptedBalance<T>` (a single encrypted amount with a count of merged
/// u16-bounded values that bounds limb growth), plus the linear coin types `PublicCoin<T>` and
/// `EncryptedCoin<T>` that move value in and out.
module contra::balance;

use contra::{
    encrypted_amount::{
        Self,
        EncryptedAmount,
        VerifiedEncryption,
        InRangeVerifiedEncryptedAmount,
        from_value,
    },
    nizk::DdhProof,
    twisted_elgamal::{Encryption, PublicKey}
};
use sui::{
    balance::withdraw_funds_from_object,
    coin::{Coin, TreasuryCap, send_funds, redeem_funds},
    group_ops::Element,
    ristretto255::G
};

// === Errors ===

/// A value carried into the balance was encrypted under a different key.
const EInvalidPublicKey: u64 = 0;

// === Structs ===

/// A single confidential amount: an `EncryptedAmount` plus the count of u16-bounded values that
/// have been folded into it.
public struct EncryptedBalance<phantom T> has store {
    amount: EncryptedAmount,
    upper_bound: u16,
}

/// Linear wrapper around a publicly-known `u64`.
public struct PublicCoin<phantom T> has store {
    value: u64,
}

/// Linear wrapper around a verified encrypted amount.
public struct EncryptedCoin<phantom T> {
    amount: InRangeVerifiedEncryptedAmount,
}

// === PublicCoin / EncryptedCoin ===

/// A `PublicCoin` of zero value.
public(package) fun zero<T>(): PublicCoin<T> {
    PublicCoin<T> { value: 0 }
}

/// Wrap a `Coin<T>` into a `PublicCoin<T>`, sending the coin's funds to `pool`.
public(package) fun wrap<T>(coin: Coin<T>, pool: &UID): PublicCoin<T> {
    let value = coin.value();
    send_funds(coin, pool.to_address());
    PublicCoin<T> { value }
}

/// Unwrap a `PublicCoin<T>` back into a `Coin<T>`, withdrawing matching funds from `pool`.
public(package) fun unwrap<T>(coin: PublicCoin<T>, pool: &mut UID, ctx: &mut TxContext): Coin<T> {
    let PublicCoin { value } = coin;
    redeem_funds(withdraw_funds_from_object<T>(pool, value), ctx)
}

/// Merge `other` into `self`.
public(package) fun join<T>(self: &mut PublicCoin<T>, other: PublicCoin<T>) {
    let PublicCoin { value } = other;
    self.value = self.value + value;
}

/// Move the value out of `self`, leaving it at zero.
public(package) fun take<T>(self: &mut PublicCoin<T>): PublicCoin<T> {
    let value = self.value;
    self.value = 0;
    PublicCoin<T> { value }
}

/// The public value carried by `self`.
public(package) fun value<T>(self: &PublicCoin<T>): u64 {
    self.value
}

/// The verified encrypted amount carried by `coin`.
public(package) fun amount<T>(coin: &EncryptedCoin<T>): &InRangeVerifiedEncryptedAmount {
    &coin.amount
}

// === EncryptedBalance ===

/// An `EncryptedBalance` encrypting zero with `upper_bound = 1`.
public(package) fun new<T>(): EncryptedBalance<T> {
    EncryptedBalance { amount: encrypted_amount::zero(), upper_bound: 1 }
}

/// An `EncryptedBalance` encrypting zero with `upper_bound = 0`.
public(package) fun empty<T>(): EncryptedBalance<T> {
    EncryptedBalance { amount: encrypted_amount::zero(), upper_bound: 0 }
}

/// The number of u16-bounded values folded into `self`.
public(package) fun upper_bound<T>(self: &EncryptedBalance<T>): u16 {
    self.upper_bound
}

/// The largest `upper_bound` that keeps a limb within the decryption window: each limb is
/// then bounded by `0xFFFF * 0xFFFF < 2^32`.
public(package) fun max_upper_bound(): u16 {
    0xFFFF
}

/// Whether `self` is in its post-construction state (nothing merged in).
public(package) fun is_empty<T>(self: &EncryptedBalance<T>): bool {
    self.upper_bound == 0
}

/// Collapsed (single-`Encryption`) view of `self`.
public(package) fun collapse<T>(self: &EncryptedBalance<T>): Encryption {
    self.amount.collapse()
}

/// Fold `other` into `self`, leaving `other` at zero. Caller is responsible for ensuring both
/// sides are encrypted under the same key, and for any protocol-level cap on `upper_bound`.
public(package) fun merge_into<T>(self: &mut EncryptedBalance<T>, other: &mut EncryptedBalance<T>) {
    self.amount.add_assign(&other.amount);
    self.upper_bound = self.upper_bound + other.upper_bound;
    other.set_empty();
}

/// Fold an `EncryptedCoin` into `self`. Aborts if the coin's pk doesn't match the caller-supplied
/// `pk`.
public(package) fun merge_encrypted<T>(
    self: &mut EncryptedBalance<T>,
    pk: &PublicKey,
    coin: EncryptedCoin<T>,
) {
    let EncryptedCoin { amount } = coin;
    assert!(amount.pk() == pk, EInvalidPublicKey);
    self.amount.add_assign(amount.amount());
    self.upper_bound = self.upper_bound + 1;
}

/// Fold a `PublicCoin` into `self`. Zero-valued coins are no-ops (no slot consumed).
public(package) fun merge_public<T>(self: &mut EncryptedBalance<T>, coin: PublicCoin<T>) {
    let PublicCoin { value } = coin;
    if (value == 0) return;
    self.amount.add_assign(&from_value(value));
    self.upper_bound = self.upper_bound + 1;
}

/// On a verifying `proof` that `self == new_balance + value`, lower `self` to `new_balance` and
/// return `value` as a `PublicCoin`; else return `none`. Aborts if `new_balance.pk() != sender_pk`.
public(package) fun try_split_to_public<T>(
    self: &mut EncryptedBalance<T>,
    sender_pk: &PublicKey,
    new_balance: InRangeVerifiedEncryptedAmount,
    value: u64,
    proof: &DdhProof,
    dst: vector<u8>,
): Option<PublicCoin<T>> {
    assert!(new_balance.pk() == sender_pk, EInvalidPublicKey);
    let mut expected = self.collapse();
    expected.sub_assign_u64(value);
    if (new_balance.verify_equal(&expected, proof, dst)) {
        self.overwrite(&new_balance);
        option::some(PublicCoin<T> { value })
    } else {
        option::none()
    }
}

/// Split receiver-keyed coins off `self` for a batched transfer. `receiver_amounts` are the
/// per-receiver amounts and `total_sender` is the sender-keyed transfer total. Returns `some(coins)`
/// on a verifying balance proof, else `none`. Aborts if `new_balance` or `total_sender` is not keyed
/// to `sender_pk`.
///
/// `total_sender`'s commitment must equal the sum of the receiver commitments — the invariant that
/// binds the amount leaving `self` to what the receivers get. This is **not** checked here - the caller
/// (`verify_transfer_amounts`) builds `total_sender` from the receiver sum, so it holds by construction.
/// TODO: consider enforcing this structurally so `try_split_batch` need not trust the caller.
public(package) fun try_split_batch<T>(
    self: &mut EncryptedBalance<T>,
    sender_pk: &PublicKey,
    new_balance: InRangeVerifiedEncryptedAmount,
    receiver_amounts: vector<InRangeVerifiedEncryptedAmount>,
    total_sender: VerifiedEncryption,
    balance_proof: &DdhProof,
    balance_dst: vector<u8>,
): Option<vector<EncryptedCoin<T>>> {
    assert!(new_balance.pk() == sender_pk && total_sender.pk() == sender_pk, EInvalidPublicKey);

    let mut expected = self.collapse();
    expected.sub_assign(total_sender.encryption());
    if (new_balance.verify_equal(&expected, balance_proof, balance_dst)) {
        self.overwrite(&new_balance);
        option::some(receiver_amounts.map!(|amount| EncryptedCoin { amount }))
    } else {
        option::none()
    }
}

/// Re-state `self` as a verified re-encryption of the same value. Returns whether the proof
/// verified. Aborts if `new_balance.pk() != sender_pk`.
public(package) fun try_update<T>(
    self: &mut EncryptedBalance<T>,
    sender_pk: &PublicKey,
    new_balance: InRangeVerifiedEncryptedAmount,
    proof: &DdhProof,
    dst: vector<u8>,
): bool {
    assert!(new_balance.pk() == sender_pk, EInvalidPublicKey);
    if (new_balance.verify_equal(&self.collapse(), proof, dst)) {
        self.overwrite(&new_balance);
        true
    } else {
        false
    }
}

/// On a verifying `eq_proof` that `new_handles` re-key `self` (under `old_pk`) to `new_pk` — each
/// limb's commitment kept, its decryption handle mapped by a shared witness — replace `self`'s
/// amount with the re-keyed amount, preserving `upper_bound` (the re-keyed limbs encrypt the same
/// values, so their bounds are unchanged). Returns whether the proof verified. The caller is
/// responsible for updating its own record of the active key.
public(package) fun try_set_public_key<T>(
    self: &mut EncryptedBalance<T>,
    old_pk: &PublicKey,
    new_pk: &PublicKey,
    new_handles: vector<Element<G>>,
    eq_proof: DdhProof,
    dst: vector<u8>,
): bool {
    self.amount.try_rekey(old_pk, new_pk, new_handles, &eq_proof, dst).is_some_and!(|amount| {
        self.amount = *amount;
        true
    })
}

// === Admin functions ===
//
// Issuer overrides gated by `TreasuryCap`. May break consistency between circulating tokens and
// pool funds; the issuer is responsible for keeping the system consistent.

/// Overwrite `self` with a raw `EncryptedAmount`. `new` is not range-checked; `upper_bound` is
/// set to 1.
public(package) fun overwrite_unchecked<T>(
    self: &mut EncryptedBalance<T>,
    _t: &mut TreasuryCap<T>,
    new: EncryptedAmount,
) {
    self.amount = new;
    self.upper_bound = 1;
}

/// Reset `self` to zero without proof.
public(package) fun clear_unchecked<T>(self: &mut EncryptedBalance<T>, _t: &mut TreasuryCap<T>) {
    self.set_empty();
}

/// Reset a `PublicCoin` to zero without proof.
public(package) fun set_zero_unchecked<T>(self: &mut PublicCoin<T>, _t: &mut TreasuryCap<T>) {
    self.value = 0;
}

// === Private functions ===

/// Overwrite `self` with the verified amount `new`.
fun overwrite<T>(self: &mut EncryptedBalance<T>, new: &InRangeVerifiedEncryptedAmount) {
    self.amount = *new.amount();
    self.upper_bound = 1;
}

/// Reset `self` to the same state `empty()` returns.
fun set_empty<T>(self: &mut EncryptedBalance<T>) {
    self.amount = encrypted_amount::zero();
    self.upper_bound = 0;
}
