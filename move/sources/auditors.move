// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    encrypted_amount::{U32LimbHandles, WellFormedEncryptedAmount, u32_limb_encryptions},
    nizk::{ElGamalProof, verify_elgamal},
    twisted_elgamal::PublicKey
};

// === Errors ===

const EAuditorProofFailed: u64 = 1;
const EMissingAuditorData: u64 = 2;
const EUnexpectedAuditorData: u64 = 3;

// === Main Type ===

/// The auditor configuration for a confidential token: a
/// single auditor public key, plus a grace window on rotation.
///
/// Auditing is per-transfer — every transfer carries auditor-readable ciphertexts of the amount.
///
/// `current_pk == none` means auditing is disabled: transfers may carry no auditor data. On
/// `update`, the outgoing key is retained as `previous_pk` and stays valid for transfers through
/// `previous_expiration_epoch` (inclusive), so transfers built against the old key just before a
/// rotation still verify.
public struct Auditor has store {
    current_pk: Option<PublicKey>,
    previous_pk: Option<PublicKey>,
    previous_expiration_epoch: u64,
}

/// The per-transfer auditor data a sender attaches to a `batched_transfer`.
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

public(package) fun new(pk: Option<PublicKey>): Auditor {
    Auditor { current_pk: pk, previous_pk: option::none(), previous_expiration_epoch: 0 }
}

/// Rotate the auditor key. The old `current_pk` (if any) becomes `previous_pk` and remains valid for
/// transfers through `expiration_epoch`. Passing `new_pk = none` disables auditing going forward,
/// though the previous key still audits in-flight transfers until it expires. Returns the outgoing
/// key (the old `current_pk`) now retained as `previous_pk`.
public(package) fun update(
    auditor: &mut Auditor,
    new_pk: Option<PublicKey>,
    expiration_epoch: u64,
): Option<PublicKey> {
    let previous_pk = auditor.current_pk;
    auditor.previous_pk = previous_pk;
    auditor.previous_expiration_epoch = expiration_epoch;
    auditor.current_pk = new_pk;
    previous_pk
}

/// Verify a transfer's per-transfer auditor data against this auditor. `receiver_amounts` are the
/// range/consistency-proven receiver amounts and `auditor_package` is the sender-supplied data (`none`
/// when the transfer carries none). Returns the per-receiver handles to attach to events (empty when none
/// is carried) and the auditor key that verified them (`none` when none is carried).
public(package) fun verify_transfer(
    auditor: &Auditor,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    auditor_package: Option<AuditorPackage>,
    epoch: u64,
    dst: vector<u8>,
): (vector<U32LimbHandles>, Option<PublicKey>) {
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
