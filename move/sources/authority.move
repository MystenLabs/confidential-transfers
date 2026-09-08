// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Contra supports optional authority approval for protected operations. A confidential token can
/// enable one authority at a time; while enabled, each protected operation must carry an
/// `Approval<T>` over its digest in addition to the required zero-knowledge proofs. The issuer uses
/// `contra::enable_authority`, authenticated by `ManagementCap<T>`, to enable either the canonical
/// `Nitro` authority or a `Custom { id }` authority. The issuer uses `contra::disable_authority`,
/// also authenticated by `ManagementCap<T>`, to replace the active authority with
/// `AuthorityKind::None`.
///
/// For the canonical Nitro authority, see `nitro_authority.move`:
///
/// 1. The issuer creates the token's singleton `NitroAuthority<T>` with `nitro_authority::new` and
///    shares it. The issuer and designated operator configure it through the `nitro_authority`
///    module.
/// 2. The client calls `nitro_authority::new_approval`, which verifies the submitted signature
///    against a registered key and invokes package-private
///    `contra::mint_nitro_authority_approval`.
/// 3. The client passes the resulting `Option<Approval<T>>` to a protected operation. Contra
///    requires it while the authority is enabled, reconstructs the operation binding, and validates
///    and consumes the approval against that binding.
///
/// A custom authority creates and privately stores an `AuthorityCap<T>` bound to its object ID. The
/// issuer enables `Custom { id }`; after performing its own checks, the authority calls
/// `contra::mint_custom_authority_approval` to mint an approval.
module contra::authority;

use contra::{encrypted_amount::EncryptedAmount, twisted_elgamal::PublicKey};
use sui::{bcs, hash::blake2b256};

// === Errors ===

const EApprovalMismatch: u64 = 0;
const EWrongAuthority: u64 = 1;
const EApprovalRequired: u64 = 2;

// === Types ===

/// Token-specific capability bound to an authority object's ID. A custom authority implementation
/// stores it privately and presents it to `mint_custom_authority_approval`.
public struct AuthorityCap<phantom T> has store {
    authority_id: ID,
}

/// Identifies an authority implementation.
public enum AuthorityKind has copy, drop, store {
    /// Authority checks are disabled while this variant is configured.
    None,
    /// Contra's canonical Nitro enclave authority.
    Nitro,
    /// A custom authority implemented by another package.
    Custom { id: ID },
}

/// A one-use hot-potato approval bound to one operation digest. It must be consumed by a protected
/// operation in the same PTB.
public struct Approval<phantom T> {
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

/// Return `AuthorityKind::None`. `contra` uses this package-only function when creating a
/// confidential token and disabling authority checks.
public(package) fun none(): AuthorityKind {
    AuthorityKind::None
}

/// Whether `authority` is `AuthorityKind::None`. `contra` uses this package-only function before
/// minting or consuming an approval and when updating the configured authority.
public(package) fun is_none(authority: &AuthorityKind): bool {
    *authority == AuthorityKind::None
}

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
    Approval { digest }
}

/// Mint an approval from Contra's canonical Nitro authority. `contra::mint_nitro_authority_approval`
/// calls this package-only function after signature verification, and the enabled authority must be
/// `Nitro`.
public(package) fun mint_nitro_authority_approval<T>(
    authority: &AuthorityKind,
    digest: vector<u8>,
): Approval<T> {
    assert!(*authority == AuthorityKind::Nitro, EWrongAuthority);
    Approval { digest }
}

/// Handle optional approval validation for protected operations. The binding expression is
/// evaluated only when an authority is enabled.
public(package) macro fun verify<$T>(
    $authority: &AuthorityKind,
    $approval: Option<Approval<$T>>,
    $binding: Binding,
) {
    let authority = $authority;
    let approval = $approval;
    if (is_none(authority)) {
        discard_approval(approval);
    } else {
        verify_required_approval(approval, $binding);
    };
}

/// Require, verify, and consume an approval. The `verify` macro calls this package-only function
/// only while an authority is enabled.
public(package) fun verify_required_approval<T>(approval: Option<Approval<T>>, binding: Binding) {
    let Approval { digest } = approval.destroy_or!(abort EApprovalRequired);
    assert!(digest == binding.digest(), EApprovalMismatch);
}

/// Destroy any supplied approval while `AuthorityKind::None` is configured. The `verify` macro
/// calls this package-only function after observing that authority checks are disabled. The
/// `Option` must be consumed explicitly because `Approval` does not have `drop`.
public(package) fun discard_approval<T>(approval: Option<Approval<T>>) {
    approval.do!(|approval| {
        let Approval { digest: _ } = approval;
    });
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
