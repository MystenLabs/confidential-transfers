// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// An account's confidential holdings of one token, all under one key: the spendable `active`
/// balance, the `pending` deposits, and the plaintext `public_balance` of wrapped-but-unmerged
/// coins — deposits land aside and are folded in by `merge_deposits`, so they never mutate the
/// balance a concurrent transfer is proving against. The module is closed over its own key and
/// transcript: every amount is checked against `pk`, every proof against a DST it derives itself.
module contra::balance;

use contra::{
    encrypted_amount::{
        Self,
        EncryptedAmount,
        InRangeVerifiedEncryptedAmount,
        RangeProofs,
        VerifiedEncryption,
        in_range_verified_from_value,
    },
    nizk::{DdhProof, ElGamalProof},
    twisted_elgamal::{Self, Encryption, PublicKey}
};
use sui::{
    balance::withdraw_funds_from_object,
    coin::{Coin, TreasuryCap, send_funds, redeem_funds},
    group_ops::Element,
    ristretto255::G
};

// === Errors ===

const EInvalidPublicKey: u64 = 0;
const EBalanceFull: u64 = 1;
const EPendingDepositsMustBeMerged: u64 = 2;
const EMismatchedBatchLength: u64 = 3;

// === Constants ===

/// Protocol IDs for Fiat-Shamir domain separation, appended to the caller's session id to form the
/// transcript of each proof this module verifies. Shared with the ts-sdk.
const DST_DDH: u8 = 0x01;
const DST_ELGAMAL: u8 = 0x02;
const DST_RANGE_PROOF_16: u8 = 0x04;
const DST_BATCH_DDH: u8 = 0x06;

/// The largest `upper_bound` that keeps a limb within the decryption window: each limb is then
/// bounded by `0xFFFF * 0xFFFF < 2^32`.
const MAX_UPPER_BOUND: u16 = 0xFFFF;

// === Structs ===

/// One account's holdings of token `T`: the encrypted amounts, all under `pk`, plus
/// `public_balance`, the plaintext total of public deposits credited to the pool but not yet merged.
public struct EncryptedBalance<phantom T> has store {
    pk: PublicKey,
    active: BoundedEncryptedAmount,
    pending: BoundedEncryptedAmount,
    public_balance: u64,
}

/// An `EncryptedAmount` carrying the bound on its limbs: `upper_bound` counts the u16-bounded
/// values folded into it, so every limb is at most `upper_bound * (2^16 - 1)` — nothing folded in
/// means a limb of exactly zero — and while that product fits the decryption window, the amount
/// stays decryptable.
public struct BoundedEncryptedAmount has store {
    amount: EncryptedAmount,
    upper_bound: u16,
}

/// Linear wrapper around a verified encrypted amount.
public struct EncryptedCoin<phantom T> {
    amount: InRangeVerifiedEncryptedAmount,
}

// === Construction and views ===

/// An empty `EncryptedBalance` with every amount encrypted under `pk`.
public(package) fun new<T>(pk: PublicKey): EncryptedBalance<T> {
    EncryptedBalance {
        pk,
        active: BoundedEncryptedAmount { amount: encrypted_amount::zero(), upper_bound: 0 },
        pending: BoundedEncryptedAmount { amount: encrypted_amount::zero(), upper_bound: 0 },
        public_balance: 0,
    }
}

/// The key `self`'s amounts are encrypted under. Senders read it to encrypt a deposit for `self`.
public(package) fun public_key<T>(self: &EncryptedBalance<T>): &PublicKey {
    &self.pk
}

// === Deposits ===

/// Deposit `coin`'s public value, sending its funds to `pool` and crediting the value to `self`'s
/// public deposits. Returns the deposited value. Aborts with `EBalanceFull` if `self` cannot absorb
/// the deposit.
public(package) fun deposit_public<T>(
    self: &mut EncryptedBalance<T>,
    coin: Coin<T>,
    pool: &UID,
): u64 {
    // A non-zero public balance already holds a merge slot, so topping it up needs no new one.
    assert!(self.public_balance > 0 || self.has_deposit_slot(), EBalanceFull);
    let value = coin.value();
    send_funds(coin, pool.to_address());
    self.public_balance = self.public_balance + value;
    value
}

/// Credit a receiver-keyed `EncryptedCoin` to `self`'s pending deposits, returning the amount
/// credited. Aborts with `EInvalidPublicKey` if the coin is not encrypted under `self.pk`, or with
/// `EBalanceFull` if `self` cannot absorb the deposit.
public(package) fun deposit_encrypted<T>(
    self: &mut EncryptedBalance<T>,
    coin: EncryptedCoin<T>,
): EncryptedAmount {
    assert!(self.has_deposit_slot(), EBalanceFull);
    let EncryptedCoin { amount } = coin;
    self.pending.merge_one(&self.pk, &amount);
    *amount.amount()
}

/// Fold both kinds of pending deposit into the active balance, freeing their slots. Required before
/// deposited value can be spent.
public(package) fun merge_deposits<T>(self: &mut EncryptedBalance<T>) {
    self.active.merge_into(&mut self.pending);
    let value = self.public_balance;
    self.public_balance = 0;
    // A zero-valued public deposit is a no-op, so it consumes no slot.
    if (value > 0) self.active.merge_one(&self.pk, &in_range_verified_from_value(value, self.pk));
}

// === Verification ===

/// Verify `amount` under `self.pk`: `pok` shows its four limbs are valid encryptions and
/// `range_proofs` that each limb's plaintext is a u16. The result is what `try_withdraw_public` and
/// `try_update_active` take. Aborts if either proof fails.
public(package) fun verify_amount<T>(
    self: &EncryptedBalance<T>,
    amount: EncryptedAmount,
    pok: &ElGamalProof,
    range_proofs: RangeProofs,
    session_id: vector<u8>,
): InRangeVerifiedEncryptedAmount {
    let verified = encrypted_amount::verify_encrypted_amount(
        amount,
        self.pk,
        pok,
        session_id.dst(DST_ELGAMAL),
    );
    let mut in_range = encrypted_amount::verify_in_range(
        vector[verified],
        range_proofs,
        session_id.dst(DST_RANGE_PROOF_16),
    );
    in_range.pop_back()
}

/// Verify the amounts of a batched transfer out of `self`, returning the sender-keyed transfer
/// total, the per-receiver verified amounts, and the sender's new balance — what
/// `try_withdraw_encrypted` takes.
///
/// `receiver_amounts[i]` is the transferred value re-encrypted under `receiver_pks[i]` and proven a
/// valid encryption by `receiver_encs_pok[i]`. `sender_encs_pok` folds the `new_balance` limbs and
/// the transfer total into one proof under `self.pk`, and `range_proofs` range-check every limb of
/// the receiver amounts and the new balance in one batch. The total's commitment is reconstructed
/// here from the receiver amounts, so only its sender-keyed decryption handle `total_sender_handle`
/// is supplied; that is what binds the amount leaving `self` to what the receivers are credited.
///
/// Split from `try_withdraw_encrypted` so the caller can inspect the verified receiver amounts —
/// e.g. to check a transfer's auditor data against them — before the balance is touched.
public(package) fun verify_transfer_amounts<T>(
    self: &EncryptedBalance<T>,
    receiver_pks: vector<PublicKey>,
    receiver_amounts: vector<EncryptedAmount>,
    receiver_encs_pok: vector<ElGamalProof>,
    new_balance: EncryptedAmount,
    total_sender_handle: Element<G>,
    sender_encs_pok: ElGamalProof,
    range_proofs: RangeProofs,
    session_id: vector<u8>,
): (VerifiedEncryption, vector<InRangeVerifiedEncryptedAmount>, InRangeVerifiedEncryptedAmount) {
    let n = receiver_amounts.length();
    assert!(receiver_pks.length() == n && receiver_encs_pok.length() == n, EMismatchedBatchLength);

    // Each receiver amount is proven a valid encryption under its own key.
    let mut verified_amounts = vector::tabulate!(n, |i| {
        encrypted_amount::verify_encrypted_amount(
            receiver_amounts[i],
            receiver_pks[i],
            &receiver_encs_pok[i],
            session_id.dst(DST_ELGAMAL),
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
        session_id.dst(DST_ELGAMAL),
    );
    verified_amounts.push_back(new_balance);

    // One batched range proof over every limb, grouped into the n receivers followed by the new
    // balance.
    let mut receiver_amounts = encrypted_amount::verify_in_range(
        verified_amounts,
        range_proofs,
        session_id.dst(DST_RANGE_PROOF_16),
    );
    let new_balance = receiver_amounts.pop_back();
    (total_sender, receiver_amounts, new_balance)
}

// === Withdrawals ===

/// On a verifying `balance_proof` that the active balance is `new_balance` plus `amount`, lower the
/// active balance to `new_balance` and return `amount` withdrawn from `pool` as a `Coin<T>`; on a
/// failing proof leave `self` untouched and return `none`. `new_balance` comes from `verify_amount`;
/// aborts with `EInvalidPublicKey` if it was verified under another key.
public(package) fun try_withdraw_public<T>(
    self: &mut EncryptedBalance<T>,
    amount: u64,
    new_balance: InRangeVerifiedEncryptedAmount,
    balance_proof: &DdhProof,
    session_id: vector<u8>,
    pool: &mut UID,
    ctx: &mut TxContext,
): Option<Coin<T>> {
    let mut expected = self.active.collapse();
    expected.sub_assign_u64(amount);
    if (!self.try_replace_active(&new_balance, &expected, balance_proof, session_id)) {
        return option::none()
    };
    option::some(redeem_funds(withdraw_funds_from_object<T>(pool, amount), ctx))
}

/// Split the receiver-keyed coins of a batched transfer off the active balance. Returns
/// `some(coins)` — one per receiver amount, in the same order — on a verifying balance proof, and
/// `none` (leaving `self` untouched) otherwise. All three verified inputs come from
/// `verify_transfer_amounts`; aborts with `EInvalidPublicKey` if `new_balance` or `total_sender` was
/// verified under another key.
///
/// `total_sender`'s commitment must equal the sum of the receiver commitments — the invariant that
/// binds the amount leaving `self` to what the receivers get. This is **not** re-checked here:
/// `verify_transfer_amounts` builds `total_sender` from the receiver sum, so it holds by
/// construction.
/// TODO: consider enforcing this structurally so this function need not trust its caller.
public(package) fun try_withdraw_encrypted<T>(
    self: &mut EncryptedBalance<T>,
    receiver_amounts: vector<InRangeVerifiedEncryptedAmount>,
    new_balance: InRangeVerifiedEncryptedAmount,
    total_sender: VerifiedEncryption,
    balance_proof: &DdhProof,
    session_id: vector<u8>,
): Option<vector<EncryptedCoin<T>>> {
    assert!(total_sender.pk() == &self.pk, EInvalidPublicKey);
    let mut expected = self.active.collapse();
    expected.sub_assign(total_sender.encryption());
    if (!self.try_replace_active(&new_balance, &expected, balance_proof, session_id)) {
        return option::none()
    };
    option::some(receiver_amounts.map!(|amount| EncryptedCoin { amount }))
}

// === Re-statement ===

/// Re-state the active balance as a verified re-encryption of the same value, resetting the number
/// of merges it counts as. Returns whether the balance proof verified; on failure `self` is
/// untouched. `new_balance` comes from `verify_amount`; aborts with `EInvalidPublicKey` if it was
/// verified under another key.
public(package) fun try_update_active<T>(
    self: &mut EncryptedBalance<T>,
    new_balance: InRangeVerifiedEncryptedAmount,
    balance_proof: &DdhProof,
    session_id: vector<u8>,
): bool {
    let expected = self.active.collapse();
    self.try_replace_active(&new_balance, &expected, balance_proof, session_id)
}

/// Re-key `self` from `self.pk` to `new_pk`: `rekey_proof` shows that `new_handles` re-key the
/// active balance — each limb's commitment kept, its decryption handle mapped by a shared witness —
/// which leaves the encrypted values, and so `upper_bound`, unchanged. Returns whether the proof
/// verified; on failure `self` keeps its old key and amounts.
///
/// Aborts with `EPendingDepositsMustBeMerged` if there are pending deposits: those are under the
/// old key and `rekey_proof` does not cover them. The public deposits need no re-keying, being
/// plaintext.
public(package) fun try_rekey<T>(
    self: &mut EncryptedBalance<T>,
    new_pk: PublicKey,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
    session_id: vector<u8>,
): bool {
    assert!(self.pending.upper_bound == 0, EPendingDepositsMustBeMerged);
    if (
        self
            .active
            .try_set_public_key(
                &self.pk,
                &new_pk,
                new_handles,
                rekey_proof,
                session_id.dst(DST_BATCH_DDH),
            )
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
/// WARNING: an issuer override gated by `TreasuryCap`. It may break consistency between the tokens
/// in circulation and the funds in the pool; the issuer is responsible for restoring it.
public(package) fun overwrite_unchecked<T>(
    self: &mut EncryptedBalance<T>,
    _t: &mut TreasuryCap<T>,
    new: EncryptedAmount,
) {
    self.active.amount = new;
    self.active.upper_bound = 1;
    self.pending.set_empty();
    self.public_balance = 0;
}

// === Private functions ===

/// Replace the active balance with `new_balance` if `balance_proof` shows it encrypts the same value
/// as `expected`. Returns whether the proof verified; on failure `self` is untouched. This is the
/// only place the active balance is re-stated, so every such change carries both a proof that it
/// kept the balance's value and — since a verified amount can reach us from any balance — a check
/// that it is under this balance's key.
fun try_replace_active<T>(
    self: &mut EncryptedBalance<T>,
    new_balance: &InRangeVerifiedEncryptedAmount,
    expected: &Encryption,
    balance_proof: &DdhProof,
    session_id: vector<u8>,
): bool {
    assert!(new_balance.pk() == &self.pk, EInvalidPublicKey);
    if (new_balance.verify_equal(expected, balance_proof, session_id.dst(DST_DDH))) {
        self.active.overwrite(new_balance);
        true
    } else {
        false
    }
}

/// Whether `self` can absorb one more merge. Always reserves one slot for a possible future public
/// deposit, so the cap compared against is `MAX_UPPER_BOUND - 1`.
fun has_deposit_slot<T>(self: &EncryptedBalance<T>): bool {
    MAX_UPPER_BOUND - 1 > self.active.upper_bound + self.pending.upper_bound
}

/// 21-byte Fiat-Shamir DST `session_id || protocol_id`.
fun dst(session_id: vector<u8>, protocol_id: u8): vector<u8> {
    let mut bytes = session_id;
    bytes.push_back(protocol_id);
    bytes
}

use fun dst as vector.dst;

// === BoundedEncryptedAmount ===

/// Collapsed (single-`Encryption`) view of `self`.
fun collapse(self: &BoundedEncryptedAmount): Encryption {
    self.amount.collapse()
}

/// Fold `other` into `self`, leaving `other` empty. Both sides must be under the same key.
fun merge_into(self: &mut BoundedEncryptedAmount, other: &mut BoundedEncryptedAmount) {
    self.amount.add_assign(&other.amount);
    self.upper_bound = self.upper_bound + other.upper_bound;
    other.set_empty();
}

/// Fold one u16-bounded, range-proven `amount` into `self`, the single point where value enters a
/// balance. Aborts with `EInvalidPublicKey` unless `amount` is encrypted under `pk`, the key `self`
/// is kept under: mixing keys would make the balance undecryptable by its owner.
fun merge_one(
    self: &mut BoundedEncryptedAmount,
    pk: &PublicKey,
    amount: &InRangeVerifiedEncryptedAmount,
) {
    assert!(amount.pk() == pk, EInvalidPublicKey);
    self.amount.add_assign(amount.amount());
    self.upper_bound = self.upper_bound + 1;
}

/// On a verifying `rekey_proof` that `new_handles` map `self`'s limb decryption handles from
/// `old_pk` to `new_pk` under a shared witness, adopt the re-keyed amount and return `true`. The
/// re-keyed limbs encrypt the same values, so `upper_bound` is preserved.
fun try_set_public_key(
    self: &mut BoundedEncryptedAmount,
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
fun overwrite(self: &mut BoundedEncryptedAmount, new: &InRangeVerifiedEncryptedAmount) {
    self.amount = *new.amount();
    self.upper_bound = 1;
}

/// Reset `self` to holding no value at all, freeing every slot it took.
fun set_empty(self: &mut BoundedEncryptedAmount) {
    self.amount = encrypted_amount::zero();
    self.upper_bound = 0;
}

// === Test Helpers ===

#[test_only]
public(package) fun protocol_id_ddh(): u8 { DST_DDH }

#[test_only]
public(package) fun protocol_id_elgamal(): u8 { DST_ELGAMAL }

#[test_only]
public(package) fun protocol_id_batch_ddh(): u8 { DST_BATCH_DDH }

#[test_only]
public(package) fun collapse_active<T>(self: &EncryptedBalance<T>): Encryption {
    self.active.collapse()
}

#[test_only]
public(package) fun collapse_pending<T>(self: &EncryptedBalance<T>): Encryption {
    self.pending.collapse()
}
