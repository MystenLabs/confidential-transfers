// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    encrypted_amount::{DecryptionHandles, WellFormedEncryptedAmount, with_decryption_handles},
    nizk::{MultiKeyElGamalProof, verify_multi_key_elgamal},
    twisted_elgamal::PublicKey
};

// === Errors ===

const EAuditorProofFailed: u64 = 1;
const EMissingAuditorData: u64 = 2;
const EUnexpectedAuditorData: u64 = 3;
const EMismatchedAuditorCount: u64 = 4;

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
/// receivers, …]`, so `M * N` entries for `M` auditor keys and `N` receivers — plus one batched
/// `MultiKeyElGamalProof` proving all of them consistent under the auditor keys under a single shared
/// challenge (so the whole set is verified together, not one proof per auditor).
public struct AuditorPackage has drop {
    handles: vector<DecryptionHandles>,
    proof: MultiKeyElGamalProof,
}

// === Functions ===

public fun new_auditor_package(
    handles: vector<DecryptionHandles>,
    proof: MultiKeyElGamalProof,
): AuditorPackage {
    AuditorPackage { handles, proof }
}

public(package) fun new(pks: vector<PublicKey>): Auditors {
    // Seed `previous_pks` equal to `current_pks`: no grace (and no old key) before the first `update`.
    Auditors { current_pks: pks, previous_pks: pks }
}

/// Replace both auditor key vectors wholesale. `current_pks` is tried first on a transfer, then
/// `previous_pks`; a sender-built package matches one set or the other by its key count (so the two
/// need not be the same length). The caller drives the grace policy: rotate with
/// `update(new, old_current)`, shrink the set with `update(fewer, old_current)`, end the grace with
/// `update(new, new)`, enable with `update(pks, pks)`, disable with grace via `update([], old)`, or
/// disable outright with `update([], [])`.
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
/// carries none). The single batched proof must verify against `current_pks`, and if it fails against
/// `previous_pks`. Returns, per receiver, one `DecryptionHandles` per auditor (in key order), and the
/// verifying key vector (`current_pks` or `previous_pks`), both empty when the transfer carries no
/// auditor data.
public(package) fun verify_transfer(
    auditors: &Auditors,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    auditor_package: Option<AuditorPackage>,
    dst: vector<u8>,
): (vector<vector<DecryptionHandles>>, vector<PublicKey>) {
    if (auditor_package.is_none()) {
        // No data is allowed only when auditing is off going forward (no current keys). A grace
        // window (non-empty `previous_pks`) never *requires* data, so it doesn't matter here.
        assert!(auditors.current_pks.is_empty(), EMissingAuditorData);
        return (vector[], vector[])
    };
    // Data is allowed whenever either set is active — enabled (`current_pks`) or in a grace window
    // (`previous_pks`); it is forbidden only when auditing is fully off (both sets empty).
    assert!(
        !auditors.current_pks.is_empty() || !auditors.previous_pks.is_empty(),
        EUnexpectedAuditorData,
    );
    let AuditorPackage { handles, proof } = auditor_package.destroy_some();
    let n = receiver_amounts.length();
    // The package carries one handle set per (auditor, receiver), so its auditor count is
    // `handles.length() / n`. It must match the set it will be verified against — `current_pks` or
    // `previous_pks` — otherwise the request is malformed (rather than a genuine proof failure).
    assert!(
        handles.length() == auditors.current_pks.length() * n
            || handles.length() == auditors.previous_pks.length() * n,
        EMismatchedAuditorCount,
    );
    let verifying_pks = if (
        verify_under(&handles, &proof, &auditors.current_pks, receiver_amounts, dst)
    ) {
        auditors.current_pks
    } else if (verify_under(&handles, &proof, &auditors.previous_pks, receiver_amounts, dst)) {
        auditors.previous_pks
    } else {
        abort EAuditorProofFailed
    };
    // Regroup the flat auditor-major handles into per-receiver [auditor] handles for the events.
    let m = verifying_pks.length();
    let event_handles = vector::tabulate!(n, |r| vector::tabulate!(m, |i| handles[i * n + r]));
    (event_handles, verifying_pks)
}

/// Whether the batched proof verifies for `pks`: the flat auditor-major `handles` must be exactly
/// `pks.length() * receiver_amounts.length()` long, and pairing each auditor's slice of handles with
/// the receiver amounts (`with_decryption_handles`) must satisfy `verify_multi_key_elgamal`. The
/// derived commitments are shared across auditors, so the whole set is one batched check.
fun verify_under(
    handles: &vector<DecryptionHandles>,
    proof: &MultiKeyElGamalProof,
    pks: &vector<PublicKey>,
    receiver_amounts: &vector<WellFormedEncryptedAmount>,
    dst: vector<u8>,
): bool {
    let n = receiver_amounts.length();
    let m = pks.length();
    if (handles.length() != m * n) return false;
    let encryptions_per_key = vector::tabulate!(
        m,
        |i| vector::tabulate!(
            n,
            |r| receiver_amounts[r].with_decryption_handles(&handles[i * n + r]),
        ).flatten(),
    );
    proof.verify_multi_key_elgamal(dst, pks, &encryptions_per_key)
}
