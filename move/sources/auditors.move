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

// === Constants ===

/// u32 limbs per amount — two `(lo, hi)` handles per (auditor, receiver), each with its own DDH.
const U32_LIMBS: u64 = 2;

// === Main Type ===

/// The auditor configuration for a confidential token: the `current_pks` key set (tried first on a
/// transfer) and the `previous_pks` set (also accepted, for a grace window). Auditing is per-transfer
/// — every transfer carries auditor-readable ciphertexts of the amount, one set of decryption handles
/// per auditor key.
///
/// Empty `current_pks` means auditing is disabled going forward. In steady state `current_pks ==
/// previous_pks`. A change is expressed by pointing `current_pks` at the new set while `previous_pks`
/// still holds the outgoing set, so a transfer built against either set verifies (a sender-built
/// package matches one set or the other by its key count); ending the grace sets `previous_pks` equal
/// to `current_pks`. The two sets need not be the same length — the set can shrink (`current_pks`
/// shorter, dropping an auditor) or empty out (disabling) while `previous_pks` keeps auditing in-flight
/// transfers during the grace.
public struct Auditors has store {
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
}

/// The per-transfer auditor data a sender attaches to a `batched_transfer`: the decryption handles
/// for every (auditor, receiver) pair, flat and auditor-major — `[auditor_0 × receivers, auditor_1 ×
/// receivers, …]`, so `M * N` entries (each an `[lo, hi]` pair) for `M` auditor keys and `N` receivers
/// — plus one `DdhProof` per (receiver, u32-limb) (`U32_LIMBS * N` of them, receiver-major). Since the
/// receiver's own u32 handle already anchors the limb's blinding `ρ̃` to its range/consistency-proven
/// commitment, each proof only needs to show the auditor handles re-key `ρ̃` to the auditor keys — a
/// shared-witness DDH over bases `[pk_receiver, pk_auditors…]`, no commitment re-proof.
public struct AuditorPackage has drop {
    handles: vector<vector<Element<G>>>,
    proofs: vector<DdhProof>,
}

/// One auditor's per-receiver decryption handles for a batch, tagged with that auditor's public key:
/// `handles[r]` is the `[lo, hi]` pair for receiver `r`. Held in `TransferBatch` state; `per_receiver`
/// reads one receiver's slice out of the whole set for that receiver's `TransferEvent`.
public struct VerifiedDecryptionHandlesBatch has copy, drop, store {
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
    // Seed `previous_pks` equal to `current_pks`: no grace (and no old key) before the first `update`.
    Auditors { current_pks: pks, previous_pks: pks }
}

/// Replace both auditor key vectors. `current_pks` is tried first on a transfer, then`previous_pks`.
/// The caller drives the grace policy: rotate with `update(new, old_current)`, shrink the set with 
/// `update(fewer, old_current)`, end the grace with `update(new, new)`, enable with `update(pks, pks)`. 
/// Disable with grace via `update([], old)`, or disable immediatly with `update([], [])`.
public(package) fun update(
    auditors: &mut Auditors,
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
) {
    auditors.current_pks = current_pks;
    auditors.previous_pks = previous_pks;
}

/// Verify a transfer's per-transfer auditor data. `receiver_amounts` are the range/consistency-proven
/// receiver amounts and `auditor_package` is the sender-supplied data (`none` when the transfer
/// carries none). Every per-(receiver, u32-limb) DDH must verify against `current_pks`, else against
/// `previous_pks`. Returns one `VerifiedDecryptionHandlesBatch` per auditor (in key order, each tagged with
/// the verifying key), whose `handles` are that auditor's per-receiver `[lo, hi]` pairs in submission
/// order (`handles[r]` is receiver `r`'s pair); empty when the transfer carries no auditor data.
public(package) fun verify_transfer(
    auditors: &Auditors,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    auditor_package: Option<AuditorPackage>,
    dst: vector<u8>,
): vector<VerifiedDecryptionHandlesBatch> {
    if (auditor_package.is_none()) {
        assert!(auditors.current_pks.is_empty(), EMissingAuditorData);
        return vector[]
    };
    assert!(
        !auditors.current_pks.is_empty() || !auditors.previous_pks.is_empty(),
        EUnexpectedAuditorData,
    );
    let AuditorPackage { handles, proofs } = auditor_package.destroy_some();
    let n = receiver_amounts.length();
    assert!(
        handles.length() == auditors.current_pks.length() * n
            || handles.length() == auditors.previous_pks.length() * n,
        EMismatchedAuditorCount,
    );
    let verifying_pks = if (
        verify_under(&handles, &proofs, &auditors.current_pks, receiver_amounts, dst)
    ) {
        auditors.current_pks
    } else if (verify_under(&handles, &proofs, &auditors.previous_pks, receiver_amounts, dst)) {
        auditors.previous_pks
    } else {
        abort EAuditorProofFailed
    };
    // One entry per auditor holding its per-receiver pairs, in submission order (`handles[r]` is
    // receiver r's pair).
    vector::tabulate!(
        verifying_pks.length(),
        |i| VerifiedDecryptionHandlesBatch {
            handles: vector::tabulate!(n, |r| handles[i * n + r]),
            pk: verifying_pks[i],
        },
    )
}

/// Receiver `receiver_index`'s slice: each auditor's `[lo, hi]` pair for that receiver together with
/// the auditor keys (both in key order) — the two fields of that receiver's `TransferEvent`. Empty
/// when `auditor_data` is empty (auditing disabled). Call with `receiver_index` `0..N-1`.
public(package) fun per_receiver(
    auditor_data: &vector<VerifiedDecryptionHandlesBatch>,
    receiver_index: u64,
): (vector<vector<Element<G>>>, vector<PublicKey>) {
    (
        auditor_data.map_ref!(|entry| entry.handles[receiver_index]),
        auditor_data.map_ref!(|entry| entry.pk),
    )
}

/// Whether every per-(receiver, u32-limb) DDH verifies for `pks`. The flat auditor-major
/// `decryption_handles` must be `pks.length() * receiver_amounts.length()` long and `proofs`
/// `U32_LIMBS * receiver_amounts.length()`. For receiver `r`, limb `l`, the DDH proves one witness
/// `ρ̃_{r,l}` maps the bases `[pk_receiver, pk_0, …, pk_{M-1}]` to the images
/// `[D_receiver, D_{0}, …, D_{M-1}]` — the receiver's own u32 handle (which the receiver's
/// consistency proof already ties to the commitment) plus each auditor's re-keyed handle for that limb.
fun verify_under(
    decryption_handles: &vector<vector<Element<G>>>,
    proofs: &vector<DdhProof>,
    pks: &vector<PublicKey>,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    dst: vector<u8>,
): bool {
    let n = receiver_amounts.length();
    let m = pks.length();
    if (decryption_handles.length() != m * n || proofs.length() != n * U32_LIMBS) return false;
    vector::tabulate!(n, |r| {
        let receiver_handles = receiver_amounts[r].handles_u32();
        let mut bases = vector[*receiver_amounts[r].pk().as_element()];
        pks.do_ref!(|pk| bases.push_back(*pk.as_element()));
        vector::tabulate!(U32_LIMBS, |l| {
            let mut images = vector[receiver_handles[l]];
            m.do!(|i| images.push_back(decryption_handles[i * n + r][l]));
            proofs[r * U32_LIMBS + l].verify_ddh(dst, &bases, &images)
        }).all!(|ok| *ok)
    }).all!(|ok| *ok)
}
