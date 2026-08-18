// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A confidential token can enable one external authority at a time. While an authority is enabled,
/// each protected operation must carry an `Approval<T>` minted using
/// its privately stored `AuthorityCap<T>` over the operation digest. This mechanism is independent
/// of the token's `Policy`.
module contra::authority;

use contra::{encrypted_amount::EncryptedAmount, events, twisted_elgamal::PublicKey};
use sui::{bcs, hash::blake2b256};

// === Errors ===

const EApprovalMismatch: u64 = 0;
const EWrongAuthority: u64 = 1;

// === Types ===

/// Token-specific capability bound to an authority object's ID. The authority implementation stores
/// it privately and presents it to authenticate that ID when minting approvals or requesting
/// enablement or disablement. Approval minting succeeds only when the authority capability's ID
/// matches the token's enabled authority ID.
public struct AuthorityCap<phantom T> has store {
    authority_id: ID,
}

/// A one-use hot-potato approval bound to the enabled authority and one operation digest. It must
/// be consumed by a protected operation in the same PTB.
public struct Approval<phantom T> {
    authority_id: ID,
    digest: vector<u8>,
}

/// The arguments an `Approval` commits to.
/// TODO: add rekey and balance update.
public enum Binding has drop {
    Transfer {
        sender_pk: PublicKey,
        receiver_pks: vector<PublicKey>,
        old_encrypted_balance: EncryptedAmount,
        new_encrypted_balance: EncryptedAmount,
        receiver_encrypted_amounts: vector<EncryptedAmount>,
    },
    Unwrap {
        sender_pk: PublicKey,
        old_encrypted_balance: EncryptedAmount,
        new_encrypted_balance: EncryptedAmount,
        amount: u64,
    },
}

// === Binding constructors ===

/// The binding of a batched transfer.
public fun transfer_binding(
    sender_pk: PublicKey,
    receiver_pks: vector<PublicKey>,
    old_encrypted_balance: EncryptedAmount,
    new_balance: &EncryptedAmount,
    receiver_amounts: &vector<EncryptedAmount>,
): Binding {
    Binding::Transfer {
        sender_pk,
        receiver_pks,
        old_encrypted_balance,
        new_encrypted_balance: *new_balance,
        receiver_encrypted_amounts: *receiver_amounts,
    }
}

/// The binding of an unwrap.
public fun unwrap_binding(
    sender_pk: PublicKey,
    old_encrypted_balance: EncryptedAmount,
    new_balance: &EncryptedAmount,
    amount: u64,
): Binding {
    Binding::Unwrap {
        sender_pk,
        old_encrypted_balance,
        new_encrypted_balance: *new_balance,
        amount,
    }
}

/// Return the canonical Blake2b-256 digest of the BCS-encoded operation binding.
public fun digest(binding: &Binding): vector<u8> {
    blake2b256(&bcs::to_bytes(binding))
}

// === Package functions ===

/// Create a token-specific capability for `authority_id`. Called by
/// `contra::new_authority_cap`, which is called by `guardian::new_guardian`.
public(package) fun new_authority_cap<T>(authority_id: ID): AuthorityCap<T> {
    AuthorityCap { authority_id }
}

/// Enable the authority represented by `authority_cap`. Called by `contra::enable_authority`.
/// Re-enabling the same authority is a no-op; enabling another authority replaces the current one.
public(package) fun enable<T>(
    enabled_authority_id: &mut Option<ID>,
    authority_cap: &AuthorityCap<T>,
) {
    if (enabled_authority_id.is_some()) {
        let current_id = enabled_authority_id.borrow_mut();
        if (*current_id == authority_cap.authority_id) return;
        events::emit_authority_disabled<T>(*current_id);
        *current_id = authority_cap.authority_id;
    } else {
        enabled_authority_id.fill(authority_cap.authority_id);
    };
    events::emit_authority_enabled<T>(authority_cap.authority_id);
}

/// Disable the enabled authority after checking its capability. Called by
/// `contra::disable_authority`.
public(package) fun disable<T>(
    enabled_authority_id: &mut Option<ID>,
    authority_cap: &AuthorityCap<T>,
) {
    if (enabled_authority_id.is_none()) return;
    let current_id = enabled_authority_id.extract();
    assert!(current_id == authority_cap.authority_id, EWrongAuthority);
    events::emit_authority_disabled<T>(current_id);
}

/// Mint an approval for `digest`; aborts unless the capability's authority ID matches the token's
/// configured authority. Called by `contra::mint_approval`.
public(package) fun mint<T>(
    authority_id: &ID,
    authority_cap: &AuthorityCap<T>,
    digest: vector<u8>,
): Approval<T> {
    assert!(*authority_id == authority_cap.authority_id, EWrongAuthority);
    Approval {
        authority_id: authority_cap.authority_id,
        digest,
    }
}

/// Destroy any supplied approval when authority checks are disabled. Called by
/// `contra::batched_transfer` and `contra::unwrap`. Because `Approval<T>` lacks `drop`, its `Option`
/// must be consumed explicitly.
public(package) fun discard_optional_approval<T>(approval: Option<Approval<T>>) {
    approval.do!(|approval| {
        let Approval { authority_id: _, digest: _ } = approval;
    });
}

/// Consume this approval against the enabled authority and operation `binding`. Called by
/// `contra::batched_transfer` and `contra::unwrap`.
public(package) fun verify_and_consume<T>(
    approval: Approval<T>,
    enabled_id: &ID,
    binding: Binding,
) {
    let Approval { authority_id, digest } = approval;
    assert!(authority_id == *enabled_id, EWrongAuthority);
    assert!(digest == binding.digest(), EApprovalMismatch);
}

// === Test helpers ===

/// Construct an authority capability directly for authority-module unit tests.
#[test_only]
public fun new_authority_cap_for_testing<T>(authority_id: ID): AuthorityCap<T> {
    AuthorityCap { authority_id }
}
