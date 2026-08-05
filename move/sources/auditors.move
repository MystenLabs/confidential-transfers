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

/// The per-transfer auditor data a sender attaches to a `batched_transfer`: one `U32LimbHandles`
/// (two u32-limb decryption handles) per receiver, in receiver order, plus one batched `ElGamalProof`
/// proving those handles well-formed under the auditor key.
public struct AuditorPackage has drop {
    handles: vector<U32LimbHandles>,
    proof: ElGamalProof,
}

// === Functions ===

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

public(package) fun new(pk: Option<Element<G>>): Auditor {
    assert_non_identity(&pk);
    Auditor { current_pk: pk, previous_pk: option::none(), previous_expiration_epoch: 0 }
}

/// Rotate the auditor key. The old `current_pk` (if any) becomes `previous_pk` and remains valid for
/// transfers through `expiration_epoch`. Passing `new_pk = none` disables auditing going forward,
/// though the previous key still audits in-flight transfers until it expires. Returns the outgoing
/// key (the old `current_pk`) now retained as `previous_pk`.
public(package) fun update(
    auditor: &mut Auditor,
    new_pk: Option<Element<G>>,
    expiration_epoch: u64,
): Option<Element<G>> {
    assert_non_identity(&new_pk);
    let previous_pk = auditor.current_pk;
    auditor.previous_pk = previous_pk;
    auditor.previous_expiration_epoch = expiration_epoch;
    auditor.current_pk = new_pk;
    previous_pk
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
        assert!(auditor.current_pk.is_none(), EMissingAuditorData);
        return (vector[], option::none())
    };
    assert!(
        auditor.current_pk.is_some() ||
            (epoch <= auditor.previous_expiration_epoch && auditor.previous_pk.is_some()),
        EUnexpectedAuditorData,
    );
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

/// Abort with `EIdentityAuditorPublicKey` if `pk` is set to the group identity.
fun assert_non_identity(pk: &Option<Element<G>>) {
    pk.do_ref!(|k| assert!(*k != g_identity(), EIdentityAuditorPublicKey));
}
