// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::encrypted_amount;

use contra::{
    nizk::{DdhProof, ElGamalProof, verify_ddh, verify_elgamal},
    twisted_elgamal::{Self, Encryption, g, encrypt_trivial, encrypt_zero}
};
use sui::{
    group_ops::Element,
    rangeproofs,
    ristretto255::{G, g_add, g_identity, g_mul, scalar_from_u64}
};

/// Bulletproof construction version. `0` is the original Bulletproofs construction
/// (Bünz et al., 2018), the only version currently supported by
/// `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255`.
const BULLETPROOFS_VERSION: u8 = 0;

/// Bit-length used by the per-limb range check: each limb encrypts a u16, so the proof
/// must show every committed value lies in `[0, 2^16)`.
const LIMB_BITS: u8 = 16;

/// Maximum number of amounts covered by a single Bulletproof chunk.
/// `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255` caps the aggregated commitment
/// count at 32 for `LIMB_BITS = 16`, and each amount contributes 4 limb commitments, so a single proof
/// covers at most `32 / 4 = 8` amounts.
const MAX_BATCH_SIZE: u64 = 8;

const EIndexOutOfBounds: u64 = 2;
const EMismatchedBatchLength: u64 = 3;
const EWellFormedProofFailed: u64 = 4;
const ERangeProofRequired: u64 = 5;

/// Encrypted u64 amount stored as four u16 limbs that may overflow to at most u32.
/// The value is `l0 + 2^16 * l1 + 2^32 * l2 + 2^48 * l3`.
/// Overflows are prevented by the higher level protocols.
public struct EncryptedAmount has copy, drop, store {
    l0: Encryption,
    l1: Encryption,
    l2: Encryption,
    l3: Encryption,
}

/// A wrapper around EncryptedAmount that has been verified to have the following properties:
/// 1) The plaintexts for all limbs are at most 2^16.
/// 2) All limbs are valid encryptions with respect to the given public key (in the Proof of Knowledge sense).
public struct WellFormedEncryptedAmount has copy, drop {
    amount: EncryptedAmount,
    pk: Element<G>,
}

/// Per-amount ElGamal consistency. The public key isn't stored
/// here — the verifier supplies it at `verify` time.
public struct ConsistencyProof has drop {
    proof: ElGamalProof,
}

/// Well-formedness proof: one Bulletproof per chunk of the canonical partition of
/// `consistency_proofs.length()` (see `batch_sizes`; e.g. N=7 → [4, 2, 1], N=20 → [8, 8, 4]),
/// plus one `ConsistencyProof` per amount. An empty `range_proofs` vector skips the range
/// check entirely — only reachable via the `#[test_only]` constructor.
public struct WellFormedProof has drop {
    range_proofs: vector<vector<u8>>,
    consistency_proofs: vector<ConsistencyProof>,
}

public fun new_encrypted_amount(
    l0: Encryption,
    l1: Encryption,
    l2: Encryption,
    l3: Encryption,
): EncryptedAmount {
    EncryptedAmount { l0, l1, l2, l3 }
}

public fun new_consistency_proof(proof: ElGamalProof): ConsistencyProof {
    ConsistencyProof { proof }
}

/// Bundle range proofs and consistency proofs into a `WellFormedProof`. Pass one consistency
/// proof per amount and one range proof per `batch_sizes(consistency_proofs.length())` chunk,
/// where each chunk's range proof covers that chunk's amounts (4 limbs each). Aborts on length
/// mismatch or empty `range_proofs[i]`; proofs are not verified here — callers must call
/// `verify`.
public fun new_well_formed_proof(
    range_proofs: vector<vector<u8>>,
    consistency_proofs: vector<ConsistencyProof>,
): WellFormedProof {
    assert!(
        range_proofs.length() == batch_sizes(consistency_proofs.length()).length(),
        EMismatchedBatchLength,
    );
    assert!(range_proofs.all!(|rp| !rp.is_empty()), ERangeProofRequired);
    WellFormedProof { range_proofs, consistency_proofs }
}

/// Check `proof` against `amounts` under `pks`: every limb of every amount is u16 (range proof,
/// bound to `range_dst`) and each amount is a valid ElGamal encryption to its matching `pks[i]`
/// (consistency proof, bound to `elgamal_dst`). The two DSTs are distinct so a range proof can't be
/// replayed as a consistency proof. Returns `false` on any verification failure; aborts only on
/// length mismatch between `amounts`, `pks`, and `proof.consistency_proofs`. An empty
/// `proof.range_proofs` skips the range check entirely — only reachable via the `#[test_only]`
/// constructor; `new_well_formed_proof` rejects empty input.
public(package) fun verify(
    proof: &WellFormedProof,
    elgamal_dst: vector<u8>,
    range_dst: vector<u8>,
    amounts: &vector<EncryptedAmount>,
    pks: &vector<Element<G>>,
): bool {
    let n = amounts.length();
    assert!(pks.length() == n, EMismatchedBatchLength);
    assert!(proof.consistency_proofs.length() == n, EMismatchedBatchLength);
    assert!(
        proof.range_proofs.is_empty() || proof.range_proofs.length() == batch_sizes(n).length(),
        EMismatchedBatchLength,
    );
    verify_well_formed_range_proofs(amounts, &proof.range_proofs, range_dst)
    && verify_well_formed_knowledge(amounts, &proof.consistency_proofs, pks, elgamal_dst)
}

/// Verify `proof` (a batch-of-1 `WellFormedProof`) against `amount` under `pk`, `elgamal_dst`
/// (consistency), and `range_dst` (range), and wrap into a `WellFormedEncryptedAmount`. Aborts
/// with `EWellFormedProofFailed` on failure.
public(package) fun into_well_formed(
    amount: EncryptedAmount,
    elgamal_dst: vector<u8>,
    range_dst: vector<u8>,
    pk: Element<G>,
    proof: WellFormedProof,
): WellFormedEncryptedAmount {
    assert!(
        proof.verify(elgamal_dst, range_dst, &vector[amount], &vector[pk]),
        EWellFormedProofFailed,
    );
    WellFormedEncryptedAmount { amount, pk }
}

/// Verify `proof` against `amounts` under `pks`, `elgamal_dst` (consistency), and `range_dst`
/// (range) — one aggregate proof for the whole batch — and wrap each `amounts[i]` into a
/// `WellFormedEncryptedAmount { amount, pk: pks[i] }`. Aborts with `EWellFormedProofFailed` on
/// failure.
public(package) fun batch_into_well_formed(
    amounts: vector<EncryptedAmount>,
    elgamal_dst: vector<u8>,
    range_dst: vector<u8>,
    pks: vector<Element<G>>,
    proof: WellFormedProof,
): vector<WellFormedEncryptedAmount> {
    assert!(proof.verify(elgamal_dst, range_dst, &amounts, &pks), EWellFormedProofFailed);
    amounts.zip_map!(pks, |amount, pk| WellFormedEncryptedAmount { amount, pk })
}

/// The verified encrypted amount carried by `self`.
public(package) fun amount(self: &WellFormedEncryptedAmount): &EncryptedAmount {
    &self.amount
}

/// The public key `self.amount()` is encrypted under.
public(package) fun pk(self: &WellFormedEncryptedAmount): &Element<G> {
    &self.pk
}

#[syntax(index)]
public(package) fun limb(ea: &EncryptedAmount, i: u64): &Encryption {
    assert!(i < 4, EIndexOutOfBounds);
    if (i == 0) {
        &ea.l0
    } else if (i == 1) {
        &ea.l1
    } else if (i == 2) {
        &ea.l2
    } else {
        &ea.l3
    }
}

/// Return a single encryption of the value this encrypted amount encrypts.
public(package) fun collapse(eq: &EncryptedAmount): Encryption {
    twisted_elgamal::new(
        collapse_limbs(
            eq.l0.ciphertext(),
            eq.l1.ciphertext(),
            eq.l2.ciphertext(),
            eq.l3.ciphertext(),
        ),
        collapse_limbs(
            eq.l0.decryption_handle(),
            eq.l1.decryption_handle(),
            eq.l2.decryption_handle(),
            eq.l3.decryption_handle(),
        ),
    )
}

/// Verify that `ea1` and `ea2` encrypt the same plaintext under `ea1.pk`.
public(package) fun verify_equal(
    ea1: &WellFormedEncryptedAmount,
    ea2: &Encryption,
    proof: &DdhProof,
    dst: vector<u8>,
): bool {
    let encryption = ea1.amount.collapse().sub(ea2);
    proof.verify_ddh(
        dst,
        &vector[g(), *encryption.ciphertext()],
        &vector[ea1.pk, *encryption.decryption_handle()],
    )
}

/// Re-key `old_amount` (encrypted under `old_pk`) to `new_pk` by swapping each limb's decryption
/// handle for the matching `new_handles[i]` while keeping its Pedersen commitment. On a verifying
/// batched re-keying DDH proof (Π_rekey) — a single witness `w` mapping `old_pk` and every old
/// handle to `new_pk` and `new_handles[i]` — returns the re-keyed amount; otherwise `none`. Reusing
/// the commitments means only the handles are caller-supplied, and the result encrypts the same
/// per-limb values under `new_pk` by construction.
public(package) fun try_rekey(
    old_amount: &EncryptedAmount,
    old_pk: &Element<G>,
    new_pk: &Element<G>,
    new_handles: vector<Element<G>>,
    proof: &DdhProof,
    dst: vector<u8>,
): Option<EncryptedAmount> {
    assert!(new_handles.length() == 4, EMismatchedBatchLength);
    // Pair 0 re-keys the public key; pairs 1..4 re-key each limb's decryption handle.
    let mut bases = vector[*old_pk];
    let mut images = vector[*new_pk];
    4u64.do!(|i| {
        bases.push_back(*old_amount[i].decryption_handle());
        images.push_back(new_handles[i]);
    });
    if (proof.verify_ddh(dst, &bases, &images)) {
        option::some(EncryptedAmount {
            l0: twisted_elgamal::new(*old_amount[0].ciphertext(), new_handles[0]),
            l1: twisted_elgamal::new(*old_amount[1].ciphertext(), new_handles[1]),
            l2: twisted_elgamal::new(*old_amount[2].ciphertext(), new_handles[2]),
            l3: twisted_elgamal::new(*old_amount[3].ciphertext(), new_handles[3]),
        })
    } else {
        option::none()
    }
}

/// Sum of the collapsed Pedersen commitments of `amounts` (ciphertext components only).
public(package) fun sum_commitments(amounts: &vector<WellFormedEncryptedAmount>): Element<G> {
    // `collapse_limbs` is linear, so sum the four limb positions across all amounts first (cheap
    // point adds) and collapse once, rather than collapsing each amount (three scalar mults each).
    let mut c0 = g_identity();
    let mut c1 = g_identity();
    let mut c2 = g_identity();
    let mut c3 = g_identity();
    amounts.do_ref!(|wfea| {
        let a = &wfea.amount;
        c0 = g_add(&c0, a[0].ciphertext());
        c1 = g_add(&c1, a[1].ciphertext());
        c2 = g_add(&c2, a[2].ciphertext());
        c3 = g_add(&c3, a[3].ciphertext());
    });
    collapse_limbs(&c0, &c1, &c2, &c3)
}

/// Combine four limbs into `l0 + 2^16 l1 + 2^32 l2 + 2^48 l3`.
public(package) fun collapse_limbs(
    l0: &Element<G>,
    l1: &Element<G>,
    l2: &Element<G>,
    l3: &Element<G>,
): Element<G> {
    g_add(
        l0,
        &g_add(
            &g_mul(&scalar_from_u64(1 << 16), l1),
            &g_add(
                &g_mul(&scalar_from_u64(1 << 32), l2),
                &g_mul(&scalar_from_u64(1 << 48), l3),
            ),
        ),
    )
}

public(package) fun from_value(value: u64): EncryptedAmount {
    let l0 = encrypt_trivial(value & 0xFFFF);
    let l1 = encrypt_trivial((value >> 16) & 0xFFFF);
    let l2 = encrypt_trivial((value >> 32) & 0xFFFF);
    let l3 = encrypt_trivial((value >> 48) & 0xFFFF);
    EncryptedAmount { l0, l1, l2, l3 }
}

public(package) fun zero(): EncryptedAmount {
    EncryptedAmount {
        l0: encrypt_zero(),
        l1: encrypt_zero(),
        l2: encrypt_zero(),
        l3: encrypt_zero(),
    }
}

/// Limb-wise add `b` into `a`. Limbs may exceed u16 after this.
public(package) fun add_assign(a: &mut EncryptedAmount, b: &EncryptedAmount) {
    a.l0 = a[0].add(&b[0]);
    a.l1 = a[1].add(&b[1]);
    a.l2 = a[2].add(&b[2]);
    a.l3 = a[3].add(&b[3]);
}

/// Verify every limb is in `[0, 2^16)` via one Bulletproof per chunk of `batch_sizes`. An empty
/// `range_proofs` vector skips the range check entirely (test sentinel).
fun verify_well_formed_range_proofs(
    amounts: &vector<EncryptedAmount>,
    range_proofs: &vector<vector<u8>>,
    dst: vector<u8>,
): bool {
    // For testing only: no range proofs skips the range check.
    if (range_proofs.is_empty()) return true;
    let sizes = batch_sizes(amounts.length());
    let mut offset = 0;
    sizes.zip_map_ref!(range_proofs, |chunk, range_proof| {
        let chunk = *chunk;
        let start = offset;
        offset = offset + chunk;
        rangeproofs::verify_bulletproofs_with_dst_ristretto255(
            range_proof,
            LIMB_BITS,
            &vector::tabulate!(4 * chunk, |j| *amounts[start + j / 4][j % 4].ciphertext()),
            &dst,
            BULLETPROOFS_VERSION,
        )
    }).all!(|ok| *ok)
}

/// Canonical Bulletproof chunking for `n` amounts: greedily take as many `MAX_BATCH_SIZE` chunks
/// as fit, then halve the chunk size and repeat until `n` is exhausted. Examples: n=7 → [4, 2, 1];
/// n=8 → [8]; n=16 → [8, 8]; n=20 → [8, 8, 4]; n=0 → [].
fun batch_sizes(n: u64): vector<u64> {
    let mut sizes = vector[];
    let mut remaining = n;
    let mut chunk = MAX_BATCH_SIZE;
    while (remaining > 0) {
        while (remaining >= chunk) {
            sizes.push_back(chunk);
            remaining = remaining - chunk;
        };
        chunk = chunk / 2;
    };
    sizes
}

/// Verify each limb of each `amounts[i]` is a valid ElGamal encryption under `pks[i]`.
fun verify_well_formed_knowledge(
    amounts: &vector<EncryptedAmount>,
    proofs: &vector<ConsistencyProof>,
    pks: &vector<Element<G>>,
    dst: vector<u8>,
): bool {
    let n = amounts.length();
    let mut i = 0;
    while (i < n) {
        let ea = &amounts[i];
        let limbs = vector[ea[0], ea[1], ea[2], ea[3]];
        if (!proofs[i].proof.verify_elgamal(dst, &pks[i], &limbs)) return false;
        i = i + 1;
    };
    true
}

#[test_only]
use contra::nizk::prove_elgamal;
#[test_only]
use contra::twisted_elgamal::encrypt_trivial_for_testing;

#[test_only]
public fun total_consistency_proof_for_testing(
    dst: vector<u8>,
    value: u64,
    r: u64,
    pk: &Element<G>,
): ElGamalProof {
    let enc = encrypt_trivial_for_testing(value, pk, r);
    prove_elgamal(
        dst,
        pk,
        &vector[enc],
        &vector[value],
        &vector[r],
        &scalar_from_u64(1234),
        &scalar_from_u64(5678),
    )
}

/// Test-only `WellFormedProof` with no range proofs — an empty `range_proofs` vector is the
/// sentinel that tells `verify` to skip the range check. Move tests can't produce real
/// Bulletproof bytes; they bound limbs out of band.
#[test_only]
public fun new_well_formed_proof_for_testing(
    consistency_proofs: vector<ConsistencyProof>,
): WellFormedProof {
    WellFormedProof { range_proofs: vector[], consistency_proofs }
}

#[test_only]
public fun new_well_formed_proof_singleton_for_testing(
    consistency_proof: ConsistencyProof,
): WellFormedProof {
    new_well_formed_proof_for_testing(vector[consistency_proof])
}

#[test_only]
public fun collapse_for_testing(ea: &EncryptedAmount): Encryption {
    ea.collapse()
}

/// The four limb decryption handles of `ea`, in order — the `new_handles` argument `try_rekey`
/// expects.
#[test_only]
public fun decryption_handles_for_testing(ea: &EncryptedAmount): vector<Element<G>> {
    vector[
        *ea[0].decryption_handle(),
        *ea[1].decryption_handle(),
        *ea[2].decryption_handle(),
        *ea[3].decryption_handle(),
    ]
}

#[test_only]
public fun limb_for_testing(ea: &EncryptedAmount, i: u64): Encryption {
    *ea.limb(i)
}

#[test_only]
public fun consistency_proof_for_testing(
    dst: vector<u8>,
    amount: u16,
    ea: &EncryptedAmount,
    blinding: u64,
    pk: &Element<G>,
): ConsistencyProof {
    let e0 = ea[0];
    let e1 = ea[1];
    let e2 = ea[2];
    let e3 = ea[3];
    let b1 = if (*e1.decryption_handle() == g_identity()) 0 else blinding;
    let b2 = if (*e2.decryption_handle() == g_identity()) 0 else blinding;
    let b3 = if (*e3.decryption_handle() == g_identity()) 0 else blinding;
    // Limb messages are (amount, 0, 0, 0); the four share `pk`, so fold them into one proof.
    new_consistency_proof(
        prove_elgamal(
            dst,
            pk,
            &vector[e0, e1, e2, e3],
            &vector[amount as u64, 0, 0, 0],
            &vector[blinding, b1, b2, b3],
            &scalar_from_u64(1111),
            &scalar_from_u64(2222),
        ),
    )
}
