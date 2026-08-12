// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    encrypted_amount::{WellFormedEncryptedAmount, handles_u32},
    nizk::{DdhProof, verify_ddh},
    twisted_elgamal::PublicKey
};
use sui::{group_ops::Element, ristretto255::G};

// === Errors ===

const EAuditorProofFailed: u64 = 1;
const EMissingAuditorData: u64 = 2;
const EUnexpectedAuditorData: u64 = 3;
const EMismatchedAuditorCount: u64 = 4;
const ETooManyAuditors: u64 = 5;

// === Constants ===

/// u32 limbs per amount — two `(lo, hi)` handles per receiver, each verified by its own DDH.
const U32_LIMBS: u64 = 2;

// === Main Type ===

/// The auditor configuration for a confidential token: the `current_pks` key set (tried first on a
/// transfer) and the `previous_pks` set (also accepted), allowing a grace period. Each holds **at most
/// one** key (asserted by `new` / `update`). Auditing is per-transfer — every transfer carries an
/// auditor-readable copy of the amount under the auditor key. Empty `current_pks` disables auditing
/// going forward.
public struct Auditors has store {
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
}

/// The per-transfer auditor data a sender attaches to a `batched_transfer`: for the single auditor
/// key, one `[lo, hi]` decryption handle pair per receiver (`N` pairs), plus one `DdhProof` per
/// (receiver, u32-limb) (`2N` proofs, receiver-major).
public struct AuditorPackage has drop {
    handles: vector<vector<Element<G>>>,
    proofs: vector<DdhProof>,
}

/// The verified auditor decryption handles for a batch: `handles[r]` is receiver `r`'s `[lo, hi]`
/// pair, tagged with the auditor's `pk`. Held in `TransferBatch` state (as an `Option`, `none` when
/// auditing is disabled); `per_receiver` reads one receiver's pair for that receiver's `TransferEvent`.
public struct VerifiedAuditorHandles has copy, drop, store {
    handles: vector<vector<Element<G>>>,
    pk: PublicKey,
}

// === Functions ===

public fun new_auditor_package(
    handles: vector<vector<Element<G>>>,
    proofs: vector<DdhProof>,
): AuditorPackage {
    AuditorPackage { handles, proofs }
}

public(package) fun new(pks: vector<PublicKey>): Auditors {
    assert!(pks.length() <= 1, ETooManyAuditors);
    // Seed `previous_pks` equal to `current_pks`: no grace (and no old key) before the first `update`.
    Auditors { current_pks: pks, previous_pks: pks }
}

/// Replace both auditor key vectors (each at most one key). `current_pks` is tried first on a transfer,
/// then `previous_pks`. The caller drives the grace policy: rotate with `update(new, old_current)`, end
/// the grace with `update(new, new)`, enable with `update(pk, pk)`, disable with grace via
/// `update([], old)`, or disable immediately with `update([], [])`.
public(package) fun update(
    auditors: &mut Auditors,
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
) {
    assert!(current_pks.length() <= 1 && previous_pks.length() <= 1, ETooManyAuditors);
    auditors.current_pks = current_pks;
    auditors.previous_pks = previous_pks;
}

/// Verify a transfer's per-transfer auditor data. `receiver_amounts` are the range/consistency-proven
/// receiver amounts and `auditor_package` is the sender-supplied data (`none` when the transfer
/// carries none). Every receiver's two per-limb DDHs must verify against `current_pks`, else against
/// `previous_pks`. Returns the verified handles tagged with the auditor key that accepted them, or
/// `none` when the transfer carries no auditor data.
public(package) fun verify_transfer(
    auditors: &Auditors,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    auditor_package: Option<AuditorPackage>,
    dst: vector<u8>,
): Option<VerifiedAuditorHandles> {
    if (auditor_package.is_none()) {
        assert!(auditors.current_pks.is_empty(), EMissingAuditorData);
        return option::none()
    };
    assert!(
        !auditors.current_pks.is_empty() || !auditors.previous_pks.is_empty(),
        EUnexpectedAuditorData,
    );
    let AuditorPackage { handles, proofs } = auditor_package.destroy_some();
    let n = receiver_amounts.length();
    // At most one auditor: exactly one `[lo, hi]` pair and one proof per receiver.
    assert!(handles.length() == n, EMismatchedAuditorCount);
    let pk = if (verify_under(&handles, &proofs, &auditors.current_pks, receiver_amounts, dst)) {
        auditors.current_pks[0]
    } else if (verify_under(&handles, &proofs, &auditors.previous_pks, receiver_amounts, dst)) {
        auditors.previous_pks[0]
    } else {
        abort EAuditorProofFailed
    };
    option::some(VerifiedAuditorHandles { handles, pk })
}

/// Receiver `receiver_index`'s auditor data as length-0-or-1 vectors: its `[lo, hi]` pair and the
/// auditor key — the two fields of that receiver's `TransferEvent`, empty when auditing is disabled.
/// Call with `receiver_index` `0..N-1`.
public(package) fun per_receiver(
    auditor_data: &Option<VerifiedAuditorHandles>,
    receiver_index: u64,
): (vector<vector<Element<G>>>, vector<PublicKey>) {
    if (auditor_data.is_none()) return (vector[], vector[]);
    let verified = auditor_data.borrow();
    (vector[verified.handles[receiver_index]], vector[verified.pk])
}

/// Whether every receiver's per-limb DDH verifies for the single key in `pks`. Returns false unless
/// `pks` holds exactly one key, `decryption_handles` has one `[lo, hi]` pair per receiver, and `proofs`
/// has one per (receiver, u32-limb). For receiver `r`, limb `l`, the DDH proves the witness `ρ̃_{r,l}`
/// maps the bases `[pk_receiver, pk_auditor]` to the images `[D_receiver, D_auditor]` — the receiver's
/// own u32 handle (which its consistency proof already ties to the commitment) plus the auditor's
/// re-keyed handle for that limb.
fun verify_under(
    decryption_handles: &vector<vector<Element<G>>>,
    proofs: &vector<DdhProof>,
    pks: &vector<PublicKey>,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    dst: vector<u8>,
): bool {
    let n = receiver_amounts.length();
    if (pks.length() != 1 || decryption_handles.length() != n || proofs.length() != n * U32_LIMBS) {
        return false
    };
    let auditor_pk = *pks[0].as_element();
    // TODO: the two per-limb DDHs share the bases `[pk_receiver, pk_auditor]` and differ only in
    // blinding. They could be folded into one batched DDH per receiver to halve the proof count.
    vector::tabulate!(n, |r| {
        let receiver_handles = receiver_amounts[r].handles_u32();
        let bases = vector[*receiver_amounts[r].pk().as_element(), auditor_pk];
        vector::tabulate!(U32_LIMBS, |l| {
            let images = vector[receiver_handles[l], decryption_handles[r][l]];
            proofs[r * U32_LIMBS + l].verify_ddh(dst, &bases, &images)
        }).all!(|ok| *ok)
    }).all!(|ok| *ok)
}
