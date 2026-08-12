// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    encrypted_amount::{WellFormedEncryptedAmount, handles_u32},
    nizk::{DdhProof, verify_ddh_batch},
    twisted_elgamal::PublicKey
};
use sui::{group_ops::Element, ristretto255::G};

// === Errors ===

const EAuditorProofFailed: u64 = 1;
const EMissingAuditorData: u64 = 2;
const EUnexpectedAuditorData: u64 = 3;
const EMismatchedAuditorCount: u64 = 4;

// === Constants ===

/// u32 limbs per amount — two `(lo, hi)` handles per (auditor, receiver), folded into one DDH per
/// receiver (the two limbs share the receiver+auditor base set; see `nizk::verify_ddh_batch`).
const U32_LIMBS: u64 = 2;

// === Main Type ===

/// The auditor configuration for a confidential token: the `current_pks` key set (tried first on a
/// transfer) and the `previous_pks` set (also accepted), allowing a grace period. Auditing is per-transfer
/// every transfer carries auditor-readable ciphertexts of the amount, one set of decryption handles
/// per auditor key. If either `current_pks` or `previous_pks` are empty, auditing is disabled.
public struct Auditors has store {
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
}

/// The per-transfer auditor data a sender attaches to a `batched_transfer`: the decryption handles
/// for every (auditor, receiver) pair, flat and auditor-major — `[auditor_0 × receivers, auditor_1 ×
/// receivers, …]`, so `M * N` entries (each an `[lo, hi]` pair) for `M` auditor keys and `N` receivers
/// — plus one batched `DdhProof` per receiver (`N` of them), each folding that receiver's two u32
/// limbs (`nizk::verify_ddh_batch`).
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
/// carries none). Every receiver's batched DDH (over both u32 limbs) must verify against `current_pks`,
/// else against `previous_pks`. Returns one `VerifiedDecryptionHandlesBatch` per auditor (in key order, each tagged with
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

/// Whether every receiver's batched DDH verifies for `pks`. The flat auditor-major
/// `decryption_handles` must be `pks.length() * receiver_amounts.length()` long and `proofs` one per
/// receiver (`receiver_amounts.length()`). For receiver `r`, a single `verify_ddh_batch` covers both
/// u32 limbs: each limb `l` is a witness `ρ̃_{r,l}` mapping the shared bases `[pk_receiver, pk_0, …,
/// pk_{M-1}]` to the images `[D_receiver, D_{0}, …, D_{M-1}]` — the receiver's own u32 handle (which
/// the receiver's consistency proof already ties to the commitment) plus each auditor's re-keyed
/// handle for that limb. The two limbs share the base set but have independent blindings, so they fold
/// into one proof (see `nizk::verify_ddh_batch`).
fun verify_under(
    decryption_handles: &vector<vector<Element<G>>>,
    proofs: &vector<DdhProof>,
    pks: &vector<PublicKey>,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    dst: vector<u8>,
): bool {
    let n = receiver_amounts.length();
    let m = pks.length();
    if (decryption_handles.length() != m * n || proofs.length() != n) return false;
    vector::tabulate!(n, |r| {
        let receiver_handles = receiver_amounts[r].handles_u32();
        let mut bases = vector[*receiver_amounts[r].pk().as_element()];
        pks.do_ref!(|pk| bases.push_back(*pk.as_element()));
        // One image vector per u32 limb (witness): [receiver handle, auditor_0 handle, …].
        let images_per_limb = vector::tabulate!(U32_LIMBS, |l| {
            let mut images = vector[receiver_handles[l]];
            m.do!(|i| images.push_back(decryption_handles[i * n + r][l]));
            images
        });
        proofs[r].verify_ddh_batch(dst, &bases, &images_per_limb)
    }).all!(|ok| *ok)
}
