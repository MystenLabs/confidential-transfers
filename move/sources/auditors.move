// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    encrypted_amount::{DecryptionHandles, WellFormedEncryptedAmount, with_decryption_handles},
    nizk::{ElGamalProof, verify_elgamal},
    twisted_elgamal::PublicKey
};

// === Errors ===

const EAuditorProofFailed: u64 = 1;
const EMissingAuditorData: u64 = 2;
const EUnexpectedAuditorData: u64 = 3;
const EMismatchedAuditorCount: u64 = 4;

// === Main Type ===

/// The auditor configuration for a confidential token: parallel `current_pks` / `previous_pks` key
/// vectors of the same length. Auditing is per-transfer — every transfer carries auditor-readable
/// ciphertexts of the amount, one set of decryption handles per auditor key.
///
/// Empty vectors mean auditing is disabled. In steady state `current_pks == previous_pks`. A rotation
/// grace is expressed by pointing `current_pks` at the new keys while `previous_pks` still holds the
/// outgoing keys, so a transfer built against either set verifies; ending the grace sets
/// `previous_pks` back equal to `current_pks`. The two vectors are kept the same length so one
/// sender-built package (one entry per key) can be checked against either set.
public struct Auditors has store {
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
}

/// The per-transfer auditor data a sender attaches to a `batched_transfer`: one `AuditorEntry` per
/// auditor key (in key order), each carrying that auditor's per-receiver decryption handles and a
/// batched proof.
public struct AuditorPackage has drop {
    entries: vector<AuditorEntry>,
}

/// One auditor's share of a transfer: its per-receiver `DecryptionHandles` and a single batched
/// `ElGamalProof` over that auditor's derived u32-limb encryptions (all under one key).
public struct AuditorEntry has drop {
    handles: vector<DecryptionHandles>,
    proof: ElGamalProof,
}

// === Functions ===

public fun new_auditor_entry(
    handles: vector<DecryptionHandles>,
    proof: ElGamalProof,
): AuditorEntry {
    AuditorEntry { handles, proof }
}

public fun new_auditor_package(entries: vector<AuditorEntry>): AuditorPackage {
    AuditorPackage { entries }
}

public(package) fun new(pks: vector<PublicKey>): Auditors {
    // Seed `previous_pks` equal to `current_pks`: no grace (and no old key) before the first `update`.
    Auditors { current_pks: pks, previous_pks: pks }
}

/// Replace both auditor key vectors wholesale, asserting they are the same length (so one
/// sender-built package covers either set). `current_pks` is tried first on a transfer, then
/// `previous_pks`. The caller drives the grace policy: rotate with `update(new, old_current)`, end
/// the grace with `update(new, new)`, enable with `update(pks, pks)`, disable with `update([], [])`.
public(package) fun update(
    auditors: &mut Auditors,
    current_pks: vector<PublicKey>,
    previous_pks: vector<PublicKey>,
) {
    assert!(current_pks.length() == previous_pks.length(), EMismatchedAuditorCount);
    auditors.current_pks = current_pks;
    auditors.previous_pks = previous_pks;
}

/// Verify a transfer's per-transfer auditor data. `receiver_amounts` are the range/consistency-proven
/// receiver amounts and `auditor_package` is the sender-supplied data (`none` when the transfer
/// carries none). Every auditor's batched proof must verify under `current_pks`, and if any fails the
/// whole set is retried under `previous_pks`. Returns, per receiver, one `DecryptionHandles` per
/// auditor (in key order), and the verifying key vector (`current_pks` or `previous_pks`), both empty
/// when the transfer carries no auditor data.
public(package) fun verify_transfer(
    auditors: &Auditors,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    auditor_package: Option<AuditorPackage>,
    dst: vector<u8>,
): (vector<vector<DecryptionHandles>>, vector<PublicKey>) {
    if (auditor_package.is_none()) {
        // The same-length invariant makes empty `current_pks` equivalent to auditing disabled.
        assert!(auditors.current_pks.is_empty(), EMissingAuditorData);
        return (vector[], vector[])
    };
    assert!(!auditors.current_pks.is_empty(), EUnexpectedAuditorData);
    let AuditorPackage { entries } = auditor_package.destroy_some();
    let verifying_pks = if (verify_under(&entries, &auditors.current_pks, receiver_amounts, dst)) {
        auditors.current_pks
    } else if (verify_under(&entries, &auditors.previous_pks, receiver_amounts, dst)) {
        auditors.previous_pks
    } else {
        abort EAuditorProofFailed
    };
    // Transpose the [auditor][receiver] handles into [receiver][auditor] for the per-receiver events.
    let handles = vector::tabulate!(
        receiver_amounts.length(),
        |i| entries.map_ref!(|entry| entry.handles[i]),
    );
    (handles, verifying_pks)
}

/// Whether every auditor entry's batched proof verifies under its paired key in `pks`. A length
/// mismatch between `entries` and `pks` (e.g. a package built for a differently-sized set) fails
/// without evaluating any proof.
fun verify_under(
    entries: &vector<AuditorEntry>,
    pks: &vector<PublicKey>,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    dst: vector<u8>,
): bool {
    entries.length() == pks.length() &&
        entries.zip_map_ref!(pks, |entry, pk| {
            let encryptions = receiver_amounts
                .zip_map_ref!(&entry.handles, |wfea, dh| wfea.with_decryption_handles(dh))
                .flatten();
            entry.proof.verify_elgamal(dst, pk, &encryptions)
        }).all!(|ok| *ok)
}
