// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::events;

use contra::{encrypted_amount::{EncryptedAmount, DecryptionHandles}, twisted_elgamal::PublicKey};
use sui::{event, group_ops::Element, ristretto255::G};

// === Events ===

/// A new confidential token is created for a token type `T`.
public struct NewConfidentialTokenEvent<phantom T>() has copy, drop;

/// A policy is updated for a confidential token.
public struct PolicyUpdateEvent<phantom T, phantom W>(vector<u8>) has copy, drop;

/// A new token account is registered for an account for a token type `T` with a public key `pk`.
public struct NewRegistrationEvent<phantom T> has copy, drop {
    owner: address,
    pk: PublicKey,
}

/// An account set its optional default key (used by `register_with_default_pk`) to `new_pk`, or
/// cleared it (`new_pk == none`). Per-token keys are independent of this, so it is not parameterized
/// by a token type.
public struct DefaultPkRotatedEvent has copy, drop {
    owner: address,
    new_pk: Option<PublicKey>,
}

/// Token `T`'s balance was re-keyed to `new_pk` (an explicit new key, independent of other tokens).
public struct TokenRekeyedEvent<phantom T> has copy, drop {
    owner: address,
    new_pk: PublicKey,
}

/// Emitted when `try_rekey_token_account_and_unpause` soft-fails (its re-key proof did not verify, e.g. a deposit raced).
/// Token `T` is left stale (unchanged) for a retry.
public struct TryTokenRekeyFailedEvent<phantom T> has copy, drop {
    owner: address,
}

/// A public coin is wrapped into a confidential token, adding to the pending encrypted balance of
/// an account. `memo` is an opaque caller-supplied blob, empty if none was provided.
public struct WrapEvent<phantom T> has copy, drop {
    receiver: address,
    amount: u64,
    memo: vector<u8>,
}

/// A confidential transfer is made from a sender to a receiver. The transferred amount is the
/// well-formed four-limb encryption `encrypted_amount_receiver` under `receiver_pk`. The sender
/// does not send a separate sender-keyed amount: it recovers its own outgoing value from the
/// commitments in `encrypted_amount_receiver` (the sender and receiver commitments are identical)
/// by re-deriving the per-transfer blinding from `seed = HKDF(sk * seed_point)` and
/// the receiver's `batch_index` within this transfer.
///
/// `auditor_decryption_handles` holds one `DecryptionHandles` (two u32-limb handles) per auditor key,
/// in the same order as `auditor_pks` (empty when auditing is disabled), each paired off-chain with
/// the two commitments derived from `encrypted_amount_receiver`
/// (`encrypted_amount::ciphertexts_as_u32_limbs`). `auditor_pks` are the auditor keys they are
/// encrypted under — the set (current or, during a rotation grace window, previous) that verified this
/// transfer's auditor proofs — so an auditor knows which index carries its handles. `memo` is an
/// opaque caller-supplied blob, empty if none was provided.
public struct TransferEvent<phantom T> has copy, drop {
    sender: address,
    sender_pk: PublicKey,
    seed_point: Element<G>,
    batch_index: u8,
    receiver: address,
    receiver_pk: PublicKey,
    encrypted_amount_receiver: EncryptedAmount,
    auditor_decryption_handles: vector<DecryptionHandles>,
    auditor_pks: vector<PublicKey>,
    memo: vector<u8>,
}

/// An account merges pending encrypted and public deposits to the active balance.
public struct MergeDepositsEvent<phantom T> has copy, drop {
    account: address,
}

/// An try_finalize fails because the balance proof did not verify.
/// This is only emitted s.t. the client can detect that the transfer failed and alert the user.
public struct TryTransferFailedEvent() has copy, drop;

/// Emitted when a `try_unwrap` fails due to an invalid balance proof.
public struct TryUnwrapFailedEvent() has copy, drop;

/// An amount is taken from the balance of an account and converted to public coins.
public struct UnwrapEvent<phantom T> has copy, drop {
    sender: address,
    amount: u64,
}

/// An account updates its active balance to be well-formed (e.g. after merging deposits).
public struct UpdateBalanceEvent<phantom T> has copy, drop {
    account: address,
}

/// The issuer directly overwrites the balance of an account (e.g. burn/seize).
/// `new_balance` carries the post-write encrypted amount (the bound has been
/// reset to 1 by the issuer write).
public struct SetBalanceByIssuerEvent<phantom T> has copy, drop {
    account: address,
    new_balance: EncryptedAmount,
}

/// The token is frozen globally by a freeze admin.
public struct GlobalFreezeEvent<phantom T>() has copy, drop;

/// The token is unfrozen globally by the issuer.
public struct GlobalUnfreezeEvent<phantom T>() has copy, drop;

/// An account is frozen by a freeze admin.
public struct AccountFreezeEvent<phantom T> has copy, drop {
    admin: address,
    account: address,
}

/// An account is unfrozen by the token issuer.
public struct AccountUnfreezeEvent<phantom T> has copy, drop {
    account: address,
}

/// Emitted when the auditor keys for a confidential token of type `T` are updated. `current_pks` is
/// the new key set tried first on a transfer (empty if auditing is disabled); `previous_pks` is the
/// set also accepted during a rotation grace window (same length as `current_pks`).
public struct UpdateAuditorsEvent<phantom T> has copy, drop {
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
}

// === Emit functions ===

public(package) fun emit_new_confidential_token<T>() {
    event::emit(NewConfidentialTokenEvent<T>());
}

public(package) fun emit_policy_update<T, W>(permissioned_operations: vector<u8>) {
    event::emit(PolicyUpdateEvent<T, W>(permissioned_operations));
}

public(package) fun emit_new_registration<T>(owner: address, pk: PublicKey) {
    event::emit(NewRegistrationEvent<T> { owner, pk });
}

public(package) fun emit_default_pk_rotated(owner: address, new_pk: Option<PublicKey>) {
    event::emit(DefaultPkRotatedEvent { owner, new_pk });
}

public(package) fun emit_token_rekeyed<T>(owner: address, new_pk: PublicKey) {
    event::emit(TokenRekeyedEvent<T> { owner, new_pk });
}

public(package) fun emit_try_token_rekey_failed<T>(owner: address) {
    event::emit(TryTokenRekeyFailedEvent<T> { owner });
}

public(package) fun emit_wrap<T>(receiver: address, amount: u64, memo: vector<u8>) {
    event::emit(WrapEvent<T> { receiver, amount, memo });
}

public(package) fun emit_transfer<T>(
    sender: address,
    sender_pk: PublicKey,
    seed_point: Element<G>,
    batch_index: u8,
    receiver: address,
    receiver_pk: PublicKey,
    encrypted_amount_receiver: EncryptedAmount,
    auditor_decryption_handles: vector<DecryptionHandles>,
    auditor_pks: vector<PublicKey>,
    memo: vector<u8>,
) {
    event::emit(TransferEvent<T> {
        sender,
        sender_pk,
        seed_point,
        batch_index,
        receiver,
        receiver_pk,
        encrypted_amount_receiver,
        auditor_decryption_handles,
        auditor_pks,
        memo,
    });
}

public(package) fun emit_merge_deposits<T>(account: address) {
    event::emit(MergeDepositsEvent<T> { account });
}

public(package) fun emit_try_transfer_failed() {
    event::emit(TryTransferFailedEvent());
}

public(package) fun emit_try_unwrap_failed() {
    event::emit(TryUnwrapFailedEvent());
}

public(package) fun emit_unwrap<T>(sender: address, amount: u64) {
    event::emit(UnwrapEvent<T> { sender, amount });
}

public(package) fun emit_update_balance<T>(account: address) {
    event::emit(UpdateBalanceEvent<T> { account });
}

public(package) fun emit_set_balance_by_issuer<T>(account: address, new_balance: EncryptedAmount) {
    event::emit(SetBalanceByIssuerEvent<T> { account, new_balance });
}

public(package) fun emit_global_freeze<T>() {
    event::emit(GlobalFreezeEvent<T>());
}

public(package) fun emit_global_unfreeze<T>() {
    event::emit(GlobalUnfreezeEvent<T>());
}

public(package) fun emit_account_freeze<T>(admin: address, account: address) {
    event::emit(AccountFreezeEvent<T> { admin, account });
}

public(package) fun emit_account_unfreeze<T>(account: address) {
    event::emit(AccountUnfreezeEvent<T> { account });
}

public(package) fun emit_update_auditors<T>(
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
) {
    event::emit(UpdateAuditorsEvent<T> { current_pks, previous_pks });
}
