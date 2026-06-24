// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::events;

use contra::{auditors::VerifiedKeyEncryption, encrypted_amount::EncryptedAmount};
use sui::{event, group_ops::Element, ristretto255::G};

// === Events ===

/// A new confidential token is created for a token type `T`.
public struct NewConfidentialTokenEvent<phantom T>() has copy, drop;

/// A policy is updated for a confidential token.
public struct PolicyUpdateEvent<phantom T, phantom W>(vector<u8>) has copy, drop;

/// A new token account is registered for an account for a token type `T` with a public key `pk`.
public struct NewRegistrationEvent<phantom T> has copy, drop {
    owner: address,
    pk: Element<G>,
    verified_key_encryption: VerifiedKeyEncryption,
}

/// An account has updated the public key for a token type `T`.
public struct UpdatedPublicKeyEvent<phantom T> has copy, drop {
    owner: address,
    new_pk: Element<G>,
    verified_key_encryption: VerifiedKeyEncryption,
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
/// the receiver's `batch_index` within this transfer. `memo` is an opaque caller-supplied blob,
/// empty if none was provided.
public struct TransferEvent<phantom T> has copy, drop {
    sender: address,
    sender_pk: Element<G>,
    seed_point: Element<G>,
    batch_index: u8,
    receiver: address,
    receiver_pk: Element<G>,
    encrypted_amount_receiver: EncryptedAmount,
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

/// Emitted when a `try_set_public_key_and_unpause` fails its optimistic restate.
public struct TrySetPublicKeyFailedEvent() has copy, drop;

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

/// Emitted when the auditors for a confidential token of type `T` are updated.
public struct UpdateAuditorsEvent<phantom T> has copy, drop {
    public_keys: vector<Element<G>>,
    version: u32,
    recommended_min_version: u32,
}

// === Emit functions ===

public(package) fun emit_new_confidential_token<T>() {
    event::emit(NewConfidentialTokenEvent<T>());
}

public(package) fun emit_policy_update<T, W>(permissioned_operations: vector<u8>) {
    event::emit(PolicyUpdateEvent<T, W>(permissioned_operations));
}

public(package) fun emit_new_registration<T>(
    owner: address,
    pk: Element<G>,
    verified_key_encryption: VerifiedKeyEncryption,
) {
    event::emit(NewRegistrationEvent<T> { owner, pk, verified_key_encryption });
}

public(package) fun emit_updated_public_key<T>(
    owner: address,
    new_pk: Element<G>,
    verified_key_encryption: VerifiedKeyEncryption,
) {
    event::emit(UpdatedPublicKeyEvent<T> { owner, new_pk, verified_key_encryption });
}

public(package) fun emit_wrap<T>(receiver: address, amount: u64, memo: vector<u8>) {
    event::emit(WrapEvent<T> { receiver, amount, memo });
}

public(package) fun emit_transfer<T>(
    sender: address,
    sender_pk: Element<G>,
    seed_point: Element<G>,
    batch_index: u8,
    receiver: address,
    receiver_pk: Element<G>,
    encrypted_amount_receiver: EncryptedAmount,
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

public(package) fun emit_try_set_public_key_failed() {
    event::emit(TrySetPublicKeyFailedEvent());
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
    public_keys: vector<Element<G>>,
    version: u32,
    recommended_min_version: u32,
) {
    event::emit(UpdateAuditorsEvent<T> { public_keys, version, recommended_min_version });
}
