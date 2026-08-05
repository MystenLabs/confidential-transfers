// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    encrypted_amount::{U32LimbHandles, WellFormedEncryptedAmount, u32_limb_encryptions},
    nizk::{ElGamalProof, verify_elgamal}
};
use sui::{group_ops::Element, ristretto255::{G, g_identity}};

// === Errors ===

const EIdentityAuditorPublicKey: u64 = 0;
const EAuditorProofFailed: u64 = 1;
const EMissingAuditorData: u64 = 2;
const EUnexpectedAuditorData: u64 = 3;

// === Per-transfer auditor data ===

/// The per-transfer auditor data a sender attaches to a `batched_transfer`: one `U32LimbHandles`
/// (two u32-limb decryption handles) per receiver, in receiver order, plus one batched `ElGamalProof`
/// proving those handles well-formed under the auditor key. `none` (no package) means the transfer
/// carries no auditor data.
public struct AuditorPackage has drop {
    handles: vector<U32LimbHandles>,
    proof: ElGamalProof,
}

public fun new_auditor_package(
    handles: vector<U32LimbHandles>,
    proof: ElGamalProof,
): AuditorPackage {
    AuditorPackage { handles, proof }
}

/// Consume `self` into its per-receiver handles and batched proof.
public(package) fun unpack(self: AuditorPackage): (vector<U32LimbHandles>, ElGamalProof) {
    let AuditorPackage { handles, proof } = self;
    (handles, proof)
}

// === Main Type ===

/// The auditor configuration for a confidential token under the per-transfer auditing model: a
/// single auditor public key, plus a grace window on rotation.
///
/// Auditing is per-transfer — every transfer carries auditor-readable ciphertexts of the amount
/// (see `verify_transfer`) — so the auditor never learns the user's viewing key and balances are
/// encrypted only under the user's own key.
///
/// `current_pk == none` means auditing is disabled: transfers must carry no auditor data. On
/// `update`, the outgoing key is retained as `previous_pk` and stays valid for transfers through
/// `previous_expiration_epoch` (inclusive), so transfers built against the old key just before a
/// rotation still verify.
public struct Auditor has store {
    current_pk: Option<Element<G>>,
    previous_pk: Option<Element<G>>,
    previous_expiration_epoch: u64,
}

// === Functions ===

public(package) fun new(pk: Option<Element<G>>): Auditor {
    assert_non_identity(&pk);
    Auditor { current_pk: pk, previous_pk: option::none(), previous_expiration_epoch: 0 }
}

/// Rotate the auditor key. The old `current_pk` (if any) becomes `previous_pk` and remains valid for
/// transfers through `expiration_epoch`. Passing `new_pk = none` disables auditing going forward,
/// though the previous key still audits in-flight transfers until it expires.
public(package) fun update(
    auditor: &mut Auditor,
    new_pk: Option<Element<G>>,
    expiration_epoch: u64,
) {
    assert_non_identity(&new_pk);
    auditor.previous_pk = auditor.current_pk;
    auditor.previous_expiration_epoch = expiration_epoch;
    auditor.current_pk = new_pk;
}

/// Whether auditing is currently enabled (a current key is set). A transfer MUST attach auditor data
/// when this is true.
public(package) fun is_enabled(auditor: &Auditor): bool {
    auditor.current_pk.is_some()
}

/// Whether a transfer's auditor data can be verified at `epoch`: either a current key is set, or the
/// previous key is still within its grace window. When a token is disabled (`current_pk == none`) but
/// the previous key is still in grace, auditor data is OPTIONAL — a transfer may still attach it (so
/// in-flight transfers built against the old key remain auditable), but need not. When this is false,
/// a transfer must carry no auditor data.
public(package) fun accepts_at(auditor: &Auditor, epoch: u64): bool {
    auditor.current_pk.is_some() ||
        (epoch <= auditor.previous_expiration_epoch && auditor.previous_pk.is_some())
}

/// Verify a transfer's per-transfer auditor data against this auditor. `receiver_amounts` are the
/// range/consistency-proven receiver amounts; `auditor_package` is the sender-supplied data (`none`
/// when the transfer carries none), holding one `U32LimbHandles` per receiver plus one batched
/// `ElGamalProof` over the derived u32-limb `(commitment, handle)` pairs (the commitments come from
/// `receiver_amounts` itself). Returns the per-receiver handles to attach to events (empty when none
/// is carried) and the auditor key that verified them (`none` when none is carried).
///
/// Presence policy: auditor data is required when auditing is enabled, forbidden when fully off, and
/// optional during a disable grace window (verified under the previous key so in-flight transfers
/// stay auditable). Aborts if that policy is violated (`EMissingAuditorData` / `EUnexpectedAuditorData`)
/// or the proof verifies under no accepted key at `epoch` (`EAuditorProofFailed`). The proof is
/// accepted under the current key, or the previous key while `epoch <= previous_expiration_epoch`.
public(package) fun verify_transfer(
    auditor: &Auditor,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    auditor_package: Option<AuditorPackage>,
    epoch: u64,
    dst: vector<u8>,
): (vector<U32LimbHandles>, Option<Element<G>>) {
    if (auditor_package.is_none()) {
        assert!(!auditor.is_enabled(), EMissingAuditorData);
        return (vector[], option::none())
    };
    assert!(auditor.accepts_at(epoch), EUnexpectedAuditorData);
    let (handles, proof) = auditor_package.destroy_some().unpack();
    let encryptions = u32_limb_encryptions(receiver_amounts, &handles);
    // Accept under the current key, or the previous key while in its grace window.
    if (auditor.current_pk.is_some_and!(|pk| proof.verify_elgamal(dst, pk, &encryptions))) {
        return (handles, auditor.current_pk)
    };
    if (
        epoch <= auditor.previous_expiration_epoch &&
            auditor.previous_pk.is_some_and!(|pk| proof.verify_elgamal(dst, pk, &encryptions))
    ) {
        return (handles, auditor.previous_pk)
    };
    abort EAuditorProofFailed
}

public(package) fun current_pk(auditor: &Auditor): Option<Element<G>> {
    auditor.current_pk
}

public(package) fun previous_pk(auditor: &Auditor): Option<Element<G>> {
    auditor.previous_pk
}

public(package) fun previous_expiration_epoch(auditor: &Auditor): u64 {
    auditor.previous_expiration_epoch
}

/// Abort with `EIdentityAuditorPublicKey` if `pk` is set to the group identity.
fun assert_non_identity(pk: &Option<Element<G>>) {
    pk.do_ref!(|k| assert!(*k != g_identity(), EIdentityAuditorPublicKey));
}
