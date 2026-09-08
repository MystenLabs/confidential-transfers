// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A confidential token can enable one authority at a time. When an authority is enabled, each
/// protected operation must carry an `Approval<T>` over the operation digest in addition to its
/// required zero-knowledge proofs. Custom authority implementations authenticate with a privately
/// stored `AuthorityCap<T>`; Contra's canonical Nitro authority uses package-private functions.
module contra::authority;

use contra::{encrypted_amount::EncryptedAmount, twisted_elgamal::PublicKey};
use sui::{bcs, hash::blake2b256};

// === Errors ===

const EApprovalMismatch: u64 = 0;
const EWrongAuthority: u64 = 1;

// === Types ===

/// Token-specific capability bound to an authority object's ID. A custom authority implementation
/// stores it privately and presents it to `mint_custom_authority_approval`.
public struct AuthorityCap<phantom T> has store {
    authority_id: ID,
}

/// Identifies an authority implementation.
public enum AuthorityKind has copy, drop, store {
    /// Contra's canonical Nitro enclave authority.
    Nitro,
    /// A custom authority implemented by another package.
    Custom { id: ID },
}

/// A one-use hot-potato approval bound to the enabled authority and one operation digest. It must
/// be consumed by a protected operation in the same PTB.
public struct Approval<phantom T> {
    authority: AuthorityKind,
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

// === Package functions ===

/// Construct the operation binding for a confidential transfer. `contra::batched_transfer` calls
/// this package-only function before consuming an approval.
public(package) fun transfer_binding(
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

/// Construct the operation binding for an unwrap. `contra::unwrap` calls this package-only function
/// before consuming an approval.
public(package) fun unwrap_binding(
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

/// Create a token-specific capability for `authority_id`. `contra::new_authority_cap` calls this
/// package-only function for custom authority implementations after requiring the issuer's
/// `ManagementCap<T>`.
public(package) fun new_authority_cap<T>(authority_id: ID): AuthorityCap<T> {
    AuthorityCap { authority_id }
}

/// Mint a custom-authority approval for `digest`. `contra::mint_custom_authority_approval` calls
/// this package-only function after the custom authority's checks, and `AuthorityCap<T>` must match
/// the enabled custom authority.
public(package) fun mint_custom_authority_approval<T>(
    authority: &AuthorityKind,
    authority_cap: &AuthorityCap<T>,
    digest: vector<u8>,
): Approval<T> {
    let expected = AuthorityKind::Custom { id: authority_cap.authority_id };
    assert!(*authority == expected, EWrongAuthority);
    Approval { authority: expected, digest }
}

/// Mint an approval from Contra's canonical Nitro authority. `contra::mint_nitro_authority_approval`
/// calls this package-only function after signature verification, and the enabled authority must be
/// `Nitro`.
public(package) fun mint_nitro_authority_approval<T>(
    authority: &AuthorityKind,
    digest: vector<u8>,
): Approval<T> {
    assert!(*authority == AuthorityKind::Nitro, EWrongAuthority);
    Approval { authority: AuthorityKind::Nitro, digest }
}

/// Destroy any supplied approval when authority checks are disabled. `contra::batched_transfer` and
/// `contra::unwrap` call this package-only function after observing that authority is disabled; no
/// capability is required. The `Option` must be consumed explicitly because `Approval` does not
/// have `drop`.
public(package) fun discard_approval<T>(approval: Option<Approval<T>>) {
    approval.do!(|approval| {
        let Approval { authority: _, digest: _ } = approval;
    });
}

/// Verify and consume an approval against the enabled authority and operation `binding`.
/// `contra::batched_transfer` and `contra::unwrap` call this package-only function.
public(package) fun verify_and_consume<T>(
    approval: Approval<T>,
    enabled_authority: &AuthorityKind,
    binding: Binding,
) {
    let Approval { authority, digest } = approval;
    assert!(authority == *enabled_authority, EWrongAuthority);
    assert!(digest == binding.digest(), EApprovalMismatch);
}

// === Internal functions ===

/// Return the canonical Blake2b-256 digest of the BCS-encoded operation binding.
fun digest(binding: &Binding): vector<u8> {
    blake2b256(&bcs::to_bytes(binding))
}

// === Test helpers ===

#[test_only]
public(package) fun custom_authority_kind_for_testing(id: ID): AuthorityKind {
    AuthorityKind::Custom { id }
}

#[test_only]
public(package) fun nitro_authority_kind_for_testing(): AuthorityKind {
    AuthorityKind::Nitro
}

#[test_only]
public(package) fun digest_for_testing(binding: &Binding): vector<u8> {
    binding.digest()
}
