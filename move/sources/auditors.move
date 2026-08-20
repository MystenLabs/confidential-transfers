// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    balance::EncryptedCoin,
    encrypted_amount::ciphertexts_u32,
    nizk::{ElGamalProof, verify_elgamal},
    session_id::SessionId,
    twisted_elgamal::{Self, PublicKey, Encryption}
};
use sui::{group_ops::Element, ristretto255::G};

// === Errors ===

const EAuditorProofFailed: u64 = 0;
const EMissingAuditorData: u64 = 1;
const EUnexpectedAuditorData: u64 = 2;
const EMismatchedAuditorCount: u64 = 3;
const ETooManyAuditors: u64 = 4;

// === Constants ===

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
/// key, one decryption handle pair per receiver, plus one witness-folded `ElGamalProof` over all
/// auditor ciphertexts (each receiver's two u32 commitments paired with its two handles).
public struct AuditorPackage has drop {
    handles: vector<vector<Element<G>>>,
    proof: ElGamalProof,
}

/// The verified auditor decryption handles for a batch: `handles` holds one pair per receiver (stored
/// reversed, so `next` pops the back in submission order), tagged with the auditor's `pk`.
public struct VerifiedAuditorHandles has store {
    handles: vector<vector<Element<G>>>,
    pk: PublicKey,
}

// === Functions ===

public fun new_auditor_package(
    handles: vector<vector<Element<G>>>,
    proof: ElGamalProof,
): AuditorPackage {
    AuditorPackage { handles, proof }
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

/// Verify a transfer's per-transfer auditor data. `receiver_coins` are the coins split off the
/// sender's balance and `auditor_package` is the sender-supplied data (`none` when the transfer
/// carries none). The batched `ElGamalProof` over all `2N` auditor ciphertexts must verify against
/// `current_pks`, else against `previous_pks`. Returns the verified handles tagged with the auditor
/// key that accepted them, or `none` when the transfer carries no auditor data. The proof's
/// transcript is derived here from the transfer's `SessionId`.
public(package) fun prepare_auditor_data<T>(
    auditors: &Auditors,
    receiver_coins: &vector<EncryptedCoin<T>>,
    auditor_package: Option<AuditorPackage>,
    session_id: SessionId,
): Option<VerifiedAuditorHandles> {
    if (auditor_package.is_none()) {
        assert!(auditors.current_pks.is_empty(), EMissingAuditorData);
        return option::none()
    };
    assert!(
        !auditors.current_pks.is_empty() || !auditors.previous_pks.is_empty(),
        EUnexpectedAuditorData,
    );
    let AuditorPackage { mut handles, proof } = auditor_package.destroy_some();
    let n = receiver_coins.length();
    // At most one auditor: exactly one `[lo, hi]` handle pair per receiver.
    assert!(handles.length() == n, EMismatchedAuditorCount);
    // Build the auditor ciphertexts once; `verify_under` reuses them for both key sets.
    let encryptions = build_auditor_encryptions(&handles, receiver_coins);
    let pk = if (
        verify_under(&encryptions, &proof, &auditors.current_pks, session_id.auditor_elgamal())
    ) {
        auditors.current_pks[0]
    } else if (
        verify_under(&encryptions, &proof, &auditors.previous_pks, session_id.auditor_elgamal())
    ) {
        auditors.previous_pks[0]
    } else {
        abort EAuditorProofFailed
    };
    // Store reversed so `next` pops the back (O(1)) yet yields receivers in submission order.
    handles.reverse();
    option::some(VerifiedAuditorHandles { handles, pk })
}

/// Pop the next receiver's auditor data for its `TransferEvent`: its two `[lo, hi]` handles (empty when
/// auditing is disabled) and the auditor key (`none` when disabled). Called once per receiver.
public(package) fun next(
    auditor_data: &mut Option<VerifiedAuditorHandles>,
): (vector<Element<G>>, Option<PublicKey>) {
    if (auditor_data.is_none()) return (vector[], option::none());
    let verified = auditor_data.borrow_mut();
    (verified.handles.pop_back(), option::some(verified.pk))
}

/// Consume the auditor data once every receiver's handles have been popped by `next`. Aborts if any
/// are left, which would mean a receiver was audited but never credited.
public(package) fun destroy_empty(auditor_data: VerifiedAuditorHandles) {
    let VerifiedAuditorHandles { handles, pk: _ } = auditor_data;
    handles.destroy_empty();
}

/// Whether the batched `ElGamalProof` verifies for the single key in `pks` over the pre-built `2N`
/// auditor ciphertexts. Returns false unless `pks` holds exactly one key. Each ciphertext pairs a
/// receiver's u32 commitment (`Ǎ_{r,l}`, derived homomorphically from its range-proven u16 limbs) with
/// the sender-supplied auditor handle `D_{r,l}`; one witness-folded proof re-keys every commitment's
/// blinding to its handle under the auditor key.
fun verify_under(
    encryptions: &vector<Encryption>,
    proof: &ElGamalProof,
    pks: &vector<PublicKey>,
    dst: vector<u8>,
): bool {
    if (pks.length() != 1) return false;
    proof.verify_elgamal(dst, &pks[0], encryptions)
}

fun build_auditor_encryptions<T>(
    handles: &vector<vector<Element<G>>>,
    receiver_coins: &vector<EncryptedCoin<T>>,
): vector<Encryption> {
    let mut encryptions = vector<Encryption>[];
    receiver_coins.length().do!(|r| {
        let commitments = receiver_coins[r].amount().ciphertexts_u32();
        U32_LIMBS.do!(
            |l| encryptions.push_back(twisted_elgamal::new(commitments[l], handles[r][l])),
        );
    });
    encryptions
}
