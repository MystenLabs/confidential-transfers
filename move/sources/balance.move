// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// An account's confidential holdings of one token, all under one key: the spendable `active`
/// balance, the `pending` deposits, and the `public_balance` of wrapped-but-unmerged
/// coins — deposits land aside and are folded in by `merge_deposits`, so they never mutate the
/// balance a concurrent transfer is proving against.
module contra::balance;

use contra::{
    encrypted_amount::{Self, EncryptedAmount, RangeVerifiedAmount, VerifiedEncryption},
    nizk::{DdhProof, ElGamalProof},
    range_proof::RangeProofs,
    session_id::SessionId,
    twisted_elgamal::{Self, Encryption, PublicKey}
};
use sui::{
    balance::withdraw_funds_from_object,
    coin::{Coin, send_funds, redeem_funds},
    group_ops::Element,
    ristretto255::G
};

// === Errors ===

const EInvalidPublicKey: u64 = 0;
const EBalanceFull: u64 = 1;
const EPendingDepositsMustBeMerged: u64 = 2;
const EMismatchedBatchLength: u64 = 3;

// === Constants ===

/// The largest number of `terms` that keeps a limb within the decryption window: each limb is then
/// bounded by `0xFFFF * 0xFFFF < 2^32`.
const MAX_TERMS: u16 = 0xFFFF;

// === Structs ===

/// One account's balances of token `T`, all under `pk`: what is spendable now (`active`), what is
/// waiting to be merged (`pending`), and the plaintext total of public deposits sitting in the pool
/// (`public_balance`).
public struct Balances<phantom T> has store {
    pk: PublicKey,
    active: AccumulatedAmount,
    pending: AccumulatedAmount,
    public_balance: u64,
}

/// An `EncryptedAmount` summed from `terms` u16-bounded values, which is what bounds its limbs:
/// each is at most `terms * (2^16 - 1)`. Not an upper bound itself — it is the multiplier.
public struct AccumulatedAmount has store {
    amount: EncryptedAmount,
    terms: u16,
}

/// Linear wrapper around a verified encrypted amount.
public struct EncryptedCoin<phantom T> {
    amount: RangeVerifiedAmount,
}

// === Construction and views ===

/// An empty `Balances` with every amount encrypted under `pk`.
public(package) fun new<T>(pk: PublicKey): Balances<T> {
    Balances {
        pk,
        active: AccumulatedAmount { amount: encrypted_amount::zero(), terms: 1 },
        pending: AccumulatedAmount { amount: encrypted_amount::zero(), terms: 0 },
        public_balance: 0,
    }
}

/// The key `self`'s amounts are encrypted under. Senders read it to encrypt a deposit for `self`.
public(package) fun public_key<T>(self: &Balances<T>): &PublicKey {
    &self.pk
}

// === Deposits ===

/// Send `coin`'s funds to `pool` and credit their value to `self`'s public deposits, returning it.
public(package) fun deposit_public<T>(self: &mut Balances<T>, coin: Coin<T>, pool: &UID) {
    // A non-zero public balance already holds a merge slot, so topping it up needs no new one.
    assert!(self.public_balance > 0 || self.has_deposit_slot(), EBalanceFull);
    self.public_balance = self.public_balance + coin.value();
    send_funds(coin, pool.to_address());
}

/// Deposit an `EncryptedCoin` to `self`.
public(package) fun deposit_encrypted<T>(self: &mut Balances<T>, coin: EncryptedCoin<T>) {
    assert!(self.has_deposit_slot(), EBalanceFull);
    let EncryptedCoin { amount } = coin;
    assert!(amount.pk() == &self.pk, EInvalidPublicKey);
    self.pending.add_assign(&amount);
}

/// Fold both kinds of pending deposit into the active balance, freeing their slots.
public(package) fun merge_deposits<T>(self: &mut Balances<T>) {
    self.active.merge_into(&mut self.pending);
    let value = self.public_balance;
    self.public_balance = 0;
    if (value > 0) self.active.add_assign_value(value);
}

// === Withdrawals ===

/// On a verifying `balance_proof` that the active balance is `new_balance` plus `amount`, lower the
/// active balance to `new_balance` and return `amount` paid out of `pool`; on a failing proof
/// leave `self` untouched and return `none`. Aborts if `new_balance` fails to verify.
public(package) fun try_withdraw_public<T>(
    self: &mut Balances<T>,
    amount: u64,
    new_balance: EncryptedAmount,
    new_balance_pok: &ElGamalProof,
    new_balance_range_proofs: RangeProofs,
    balance_proof: &DdhProof,
    session_id: SessionId,
    pool: &mut UID,
    ctx: &mut TxContext,
): Option<Coin<T>> {
    let new_balance = self.verify_amount(
        new_balance,
        new_balance_pok,
        new_balance_range_proofs,
        session_id,
    );
    let mut residual = self.balance_change(&new_balance);
    residual.add_assign_u64(amount);
    if (!self.try_replace_active(&new_balance, &residual, balance_proof, session_id)) {
        return option::none()
    };
    option::some(redeem_funds(withdraw_funds_from_object<T>(pool, amount), ctx))
}

/// Split a batched transfer's receiver-keyed coins off the active balance, verifying every amount
/// first. Returns `some(coins)` — one per receiver amount, in the same order — on a verifying
/// balance proof, and `none` (leaving `self` untouched) otherwise; aborts if any amount fails to
/// verify.
///
/// The transfer total's commitment is the sum of the receiver commitments, which is what binds the
/// amount leaving `self` to what the receivers get; it is built here from those very amounts.
public(package) fun try_withdraw_batch<T>(
    self: &mut Balances<T>,
    receiver_pks: vector<PublicKey>,
    receiver_amounts: vector<EncryptedAmount>,
    receiver_encs_pok: vector<ElGamalProof>,
    new_balance: EncryptedAmount,
    total_sender_handle: Element<G>,
    sender_encs_pok: ElGamalProof,
    range_proofs: RangeProofs,
    balance_proof: &DdhProof,
    session_id: SessionId,
): Option<vector<EncryptedCoin<T>>> {
    let (receiver_amounts, new_balance, total_sender) = self.verify_transfer_amounts(
        receiver_pks,
        receiver_amounts,
        receiver_encs_pok,
        new_balance,
        total_sender_handle,
        sender_encs_pok,
        range_proofs,
        session_id,
    );
    let residual = self.balance_change(&new_balance).add(total_sender.encryption());
    if (!self.try_replace_active(&new_balance, &residual, balance_proof, session_id)) {
        return option::none()
    };
    option::some(receiver_amounts.map!(|amount| EncryptedCoin { amount }))
}

/// The verified amount `coin` carries, for a caller that must check something against it before
/// crediting it to a receiver.
public(package) fun amount<T>(coin: &EncryptedCoin<T>): &RangeVerifiedAmount {
    &coin.amount
}

// === Re-statement ===

/// Re-state the active balance as a verified re-encryption of the same value, resetting the number
/// of merges it counts as. Returns whether the balance proof verified; on failure `self` is
/// untouched. Aborts if `new_balance` fails to verify.
public(package) fun try_update_active<T>(
    self: &mut Balances<T>,
    new_balance: EncryptedAmount,
    new_balance_pok: &ElGamalProof,
    new_balance_range_proofs: RangeProofs,
    balance_proof: &DdhProof,
    session_id: SessionId,
): bool {
    let new_balance = self.verify_amount(
        new_balance,
        new_balance_pok,
        new_balance_range_proofs,
        session_id,
    );
    let residual = self.balance_change(&new_balance);
    self.try_replace_active(&new_balance, &residual, balance_proof, session_id)
}

/// Re-key `self` to `new_pk`, swapping each limb's decryption handle for the matching
/// `new_handles[i]` on a verifying `rekey_proof`. Aborts if there are pending deposits: those are
/// under the old key and the proof does not cover them.
public(package) fun try_rekey<T>(
    self: &mut Balances<T>,
    new_pk: PublicKey,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
    session_id: SessionId,
): bool {
    assert!(self.pending.terms == 0, EPendingDepositsMustBeMerged);
    if (
        self
            .active
            .try_set_public_key(&self.pk, &new_pk, new_handles, rekey_proof, session_id.batch_ddh())
    ) {
        self.pk = new_pk;
        true
    } else {
        false
    }
}

// === Admin functions ===

/// Overwrite `self` with `new` as its whole active balance, dropping every pending deposit. `new`
/// is not range-checked and is counted as a single merge.
///
/// WARNING: this may break consistency between the tokens in circulation and the funds in the pool.
public(package) fun overwrite_unchecked<T>(self: &mut Balances<T>, new: EncryptedAmount) {
    self.active.amount = new;
    self.active.terms = 1;
    self.pending.set_empty();
    self.public_balance = 0;
}

// === Private functions ===

/// Verify the amounts of a batched transfer out of `self`: the receiver amounts, the sender's new
/// balance, and the sender-keyed total the receivers sum to.
fun verify_transfer_amounts<T>(
    self: &Balances<T>,
    receiver_pks: vector<PublicKey>,
    receiver_amounts: vector<EncryptedAmount>,
    receiver_encs_pok: vector<ElGamalProof>,
    new_balance: EncryptedAmount,
    total_sender_handle: Element<G>,
    sender_encs_pok: ElGamalProof,
    range_proofs: RangeProofs,
    session_id: SessionId,
): (vector<RangeVerifiedAmount>, RangeVerifiedAmount, VerifiedEncryption) {
    let n = receiver_amounts.length();
    assert!(receiver_pks.length() == n && receiver_encs_pok.length() == n, EMismatchedBatchLength);

    // Each receiver amount is proven a valid encryption under its own key.
    let mut verified_amounts = vector::tabulate!(n, |i| {
        encrypted_amount::verify_encrypted_amount(
            receiver_amounts[i],
            receiver_pks[i],
            &receiver_encs_pok[i],
            session_id.elgamal(),
        )
    });

    // The total's commitment is reconstructed from the receiver commitments and the given handle.
    let total = twisted_elgamal::new(
        encrypted_amount::sum_ciphertexts(&receiver_amounts),
        total_sender_handle,
    );

    // Sender side: the new-balance limbs and the total are verified under `self.pk` in one proof.
    let (new_balance, total_sender) = encrypted_amount::verify_encrypted_amount_and_encryption(
        new_balance,
        total,
        self.pk,
        &sender_encs_pok,
        session_id.elgamal(),
    );
    verified_amounts.push_back(new_balance);

    // One batched range proof over every limb, grouped into the n receivers followed by the new
    // balance.
    let mut receiver_amounts = encrypted_amount::verify_in_range(
        verified_amounts,
        range_proofs,
        session_id.range_proof_16(),
    );
    let new_balance = receiver_amounts.pop_back();
    (receiver_amounts, new_balance, total_sender)
}

fun verify_amount<T>(
    self: &Balances<T>,
    amount: EncryptedAmount,
    pok: &ElGamalProof,
    range_proofs: RangeProofs,
    session_id: SessionId,
): RangeVerifiedAmount {
    let verified = encrypted_amount::verify_encrypted_amount(
        amount,
        self.pk,
        pok,
        session_id.elgamal(),
    );
    let mut in_range = encrypted_amount::verify_in_range(
        vector[verified],
        range_proofs,
        session_id.range_proof_16(),
    );
    in_range.pop_back()
}

/// The change `new_balance - active`, collapsed to a single `Encryption`.
fun balance_change<T>(self: &Balances<T>, new_balance: &RangeVerifiedAmount): Encryption {
    new_balance.amount().sub(&self.active.amount).collapse()
}

/// Replace the active balance with `new_balance` if `balance_proof` shows `residual` encrypts zero.
fun try_replace_active<T>(
    self: &mut Balances<T>,
    new_balance: &RangeVerifiedAmount,
    residual: &Encryption,
    balance_proof: &DdhProof,
    session_id: SessionId,
): bool {
    if (
        encrypted_amount::verify_zero(new_balance.pk(), residual, balance_proof, session_id.ddh())
    ) {
        self.active.overwrite(new_balance);
        true
    } else {
        false
    }
}

/// Whether `self` can absorb one more merge. Always reserves one slot for a possible future public
/// deposit, so the cap compared against is `MAX_TERMS - 1`.
fun has_deposit_slot<T>(self: &Balances<T>): bool {
    MAX_TERMS - 1 > self.active.terms + self.pending.terms
}

// === AccumulatedAmount ===

/// Collapsed (single-`Encryption`) view of `self`.
#[test_only]
fun collapse(self: &AccumulatedAmount): Encryption {
    self.amount.collapse()
}

/// Fold `other` into `self`, leaving `other` empty. Both sides must be under the same key.
fun merge_into(self: &mut AccumulatedAmount, other: &mut AccumulatedAmount) {
    self.amount.add_assign(&other.amount);
    self.terms = self.terms + other.terms;
    other.set_empty();
}

/// Fold the public `value` into `self`.
fun add_assign_value(self: &mut AccumulatedAmount, value: u64) {
    self.amount.add_assign_value(value);
    self.terms = self.terms + 1;
}

/// Fold one u16-bounded, range-proven `amount` into `self`. The caller is responsible for it being
/// under the same key.
fun add_assign(self: &mut AccumulatedAmount, amount: &RangeVerifiedAmount) {
    self.amount.add_assign(amount.amount());
    self.terms = self.terms + 1;
}

/// On a verifying `rekey_proof` that `new_handles` map `self`'s limb decryption handles from
/// `old_pk` to `new_pk` under a shared witness, adopt the re-keyed amount and return `true`. The
/// re-keyed limbs encrypt the same values, so `terms` is preserved.
fun try_set_public_key(
    self: &mut AccumulatedAmount,
    old_pk: &PublicKey,
    new_pk: &PublicKey,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
    dst: vector<u8>,
): bool {
    self.amount.try_rekey(old_pk, new_pk, new_handles, &rekey_proof, dst).is_some_and!(|amount| {
        self.amount = *amount;
        true
    })
}

/// Overwrite `self` with the verified amount `new`, which counts as a single merged value.
fun overwrite(self: &mut AccumulatedAmount, new: &RangeVerifiedAmount) {
    self.amount = *new.amount();
    self.terms = 1;
}

/// Reset `self` to holding no value at all, freeing every slot it took.
fun set_empty(self: &mut AccumulatedAmount) {
    self.amount = encrypted_amount::zero();
    self.terms = 0;
}

// === Test Helpers ===

#[test_only]
public(package) fun collapse_active<T>(self: &Balances<T>): Encryption {
    self.active.collapse()
}

#[test_only]
public(package) fun collapse_pending<T>(self: &Balances<T>): Encryption {
    self.pending.collapse()
}
