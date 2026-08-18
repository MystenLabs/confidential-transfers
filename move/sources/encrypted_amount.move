// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::encrypted_amount;

use contra::{
    nizk::{DdhProof, ElGamalProof, verify_ddh, verify_elgamal},
    twisted_elgamal::{Self, Encryption, PublicKey, g, encrypt_trivial, encrypt_zero}
};
use sui::{
    group_ops::Element,
    rangeproofs,
    ristretto255::{G, Scalar, g_add, g_identity, g_mul, scalar_from_u64}
};

/// Bulletproof construction version. `0` is the original Bulletproofs construction
/// (Bünz et al., 2018), the only version currently supported by
/// `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255`.
const BULLETPROOFS_VERSION: u8 = 0;

/// Bit-length used by the per-limb range check: each limb encrypts a u16, so the proof
/// must show every committed value lies in `[0, 2^16)`.
const LIMB_BITS: u8 = 16;

const U16_LIMBS: u64 = 4;

/// Maximum number of encryptions covered by a single Bulletproof chunk.
/// `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255` caps the aggregated commitment
/// count at 32 for `LIMB_BITS = 16`, and each encryption contributes one commitment.
const MAX_RANGE_PROOF_BATCH_SIZE: u64 = 32;

const EIndexOutOfBounds: u64 = 2;
const EMismatchedBatchLength: u64 = 3;
const EEncryptionProofFailed: u64 = 4;
const ERangeProofFailed: u64 = 5;
const ERangeProofRequired: u64 = 6;

/// Encrypted u64 amount stored as four u16 limbs that may overflow to at most u32.
/// The value is `l0 + 2^16 * l1 + 2^32 * l2 + 2^48 * l3`.
/// Overflows are prevented by the higher level protocols.
public struct EncryptedAmount has copy, drop, store {
    l0: Encryption,
    l1: Encryption,
    l2: Encryption,
    l3: Encryption,
}

/// An `Encryption` proven (via an `ElGamalProof`) to be a valid twisted-ElGamal encryption under
/// `pk` — knowledge of the blinding and message.
public struct VerifiedEncryption has drop {
    encryption: Encryption,
    pk: PublicKey,
}

/// A four-limb `EncryptedAmount` whose limbs are proven (via an `ElGamalProof`) to be valid
/// twisted-ElGamal encryptions under `pk` — knowledge of each limb's blinding and message.
public struct VerifiedEncryptedAmount has drop {
    amount: EncryptedAmount,
    pk: PublicKey,
}

/// A wrapper around EncryptedAmount that has been verified to have the following properties:
/// 1) The plaintexts for all limbs are at most 2^16.
/// 2) All limbs are valid encryptions with respect to the given public key (in the Proof of Knowledge sense).
public struct InRangeVerifiedEncryptedAmount has drop {
    amount: EncryptedAmount,
    pk: PublicKey,
}

/// The Bulletproof range proofs for a range-check batch (one per `batch_sizes` chunk). The only
/// production constructor (`new_range_proofs`) rejects an empty set, and PTBs can't fabricate a
/// struct, so a batch verified on chain can never silently skip its range check. Move tests, which
/// can't produce Bulletproof bytes, use the `#[test_only]` `assume_range_checked` instead.
public struct RangeProofs has drop {
    proofs: vector<vector<u8>>,
}

/// Wrap `proofs` into `RangeProofs`; rejects an empty set so the range check can't be skipped on chain.
public fun new_range_proofs(proofs: vector<vector<u8>>): RangeProofs {
    assert!(!proofs.is_empty() && proofs.all!(|p| !p.is_empty()), ERangeProofRequired);
    RangeProofs { proofs }
}

public fun new_encrypted_amount(
    l0: Encryption,
    l1: Encryption,
    l2: Encryption,
    l3: Encryption,
): EncryptedAmount {
    EncryptedAmount { l0, l1, l2, l3 }
}

/// Verify `amount`'s four limbs are valid encryptions under `pk` (one folded proof).
public(package) fun verify_encrypted_amount(
    amount: EncryptedAmount,
    pk: PublicKey,
    proof: &ElGamalProof,
    dst: vector<u8>,
): VerifiedEncryptedAmount {
    assert!(proof.verify_elgamal(dst, &pk, &amount.limbs()), EEncryptionProofFailed);
    VerifiedEncryptedAmount { amount, pk }
}

/// Verify `amount`'s four limbs together with the extra `encryption` under `pk` in one folded proof,
/// returning the amount and the extra separately.
public(package) fun verify_encrypted_amount_and_encryption(
    amount: EncryptedAmount,
    encryption: Encryption,
    pk: PublicKey,
    proof: &ElGamalProof,
    dst: vector<u8>,
): (VerifiedEncryptedAmount, VerifiedEncryption) {
    let mut ciphertexts = amount.limbs();
    ciphertexts.push_back(encryption);
    assert!(proof.verify_elgamal(dst, &pk, &ciphertexts), EEncryptionProofFailed);
    (VerifiedEncryptedAmount { amount, pk }, VerifiedEncryption { encryption, pk })
}

/// Range-check every limb of `amounts` (each committed value to `[0, 2^16)`) in one batch and
/// promote each to a `InRangeVerifiedEncryptedAmount`. The amounts are returned in input order.
public(package) fun verify_in_range(
    amounts: vector<VerifiedEncryptedAmount>,
    range_proofs: RangeProofs,
    dst: vector<u8>,
): vector<InRangeVerifiedEncryptedAmount> {
    let RangeProofs { proofs } = range_proofs;
    // Collect every limb commitment for the single batched range proof.
    let mut commitments = vector<Element<G>>[];
    amounts.do_ref!(|a| U16_LIMBS.do!(|i| commitments.push_back(*a.amount[i].ciphertext())));
    assert!(verify_range_proofs(&commitments, &proofs, dst), ERangeProofFailed);
    amounts.map!(|a| {
        let VerifiedEncryptedAmount { amount, pk } = a;
        InRangeVerifiedEncryptedAmount { amount, pk }
    })
}

/// The four limbs of `ea`, in order.
public(package) fun limbs(ea: &EncryptedAmount): vector<Encryption> {
    vector[ea.l0, ea.l1, ea.l2, ea.l3]
}

public(package) fun encryption(self: &VerifiedEncryption): &Encryption {
    &self.encryption
}

public(package) fun encryption_pk(self: &VerifiedEncryption): &PublicKey {
    &self.pk
}

public use fun encryption_pk as VerifiedEncryption.pk;

/// The verified encrypted amount carried by `self`.
public(package) fun amount(self: &InRangeVerifiedEncryptedAmount): &EncryptedAmount {
    &self.amount
}

/// The public key `self.amount()` is encrypted under.
public(package) fun pk(self: &InRangeVerifiedEncryptedAmount): &PublicKey {
    &self.pk
}

#[syntax(index)]
public(package) fun limb(ea: &EncryptedAmount, i: u64): &Encryption {
    assert!(i < U16_LIMBS, EIndexOutOfBounds);
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

/// The two u32-limb `Encryption`s `(l0 + 2^16 l1, l2 + 2^16 l3)` (ciphertext and handle alike).
fun collapse_to_u32(ea: &EncryptedAmount): vector<Encryption> {
    let two_16 = scalar_from_u64(1 << 16);
    vector[fold_encryption(&ea.l0, &ea.l1, &two_16), fold_encryption(&ea.l2, &ea.l3, &two_16)]
}

/// The single `Encryption` of the full u64 value: the two u32 limbs folded by `2^32`.
public(package) fun collapse(ea: &EncryptedAmount): Encryption {
    let u32s = ea.collapse_to_u32();
    fold_encryption(&u32s[0], &u32s[1], &scalar_from_u64(1 << 32))
}

/// Verify that `ea1` and `ea2` encrypt the same plaintext under `ea1.pk`.
public(package) fun verify_equal(
    ea1: &InRangeVerifiedEncryptedAmount,
    ea2: &Encryption,
    proof: &DdhProof,
    dst: vector<u8>,
): bool {
    let encryption = ea1.amount.collapse().sub(ea2);
    proof.verify_ddh(
        dst,
        &vector[g(), *encryption.ciphertext()],
        &vector[*ea1.pk.as_element(), *encryption.decryption_handle()],
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
    old_pk: &PublicKey,
    new_pk: &PublicKey,
    new_handles: vector<Element<G>>,
    proof: &DdhProof,
    dst: vector<u8>,
): Option<EncryptedAmount> {
    assert!(new_handles.length() == U16_LIMBS, EMismatchedBatchLength);
    // Pair 0 re-keys the public key and pairs 1..4 re-key each limb's decryption handle.
    let mut bases = vector[*old_pk.as_element()];
    let mut images = vector[*new_pk.as_element()];
    U16_LIMBS.do!(|i| {
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

/// Sum of the collapsed ciphertexts of `amounts` (the `r*g + m*h` component, not the handles).
public(package) fun sum_ciphertexts(amounts: &vector<EncryptedAmount>): Element<G> {
    let mut cs = vector::tabulate!(U16_LIMBS, |_| g_identity());
    amounts.do_ref!(|ea| U16_LIMBS.do!(|j| {
        let sum = g_add(&cs[j], ea[j].ciphertext());
        *cs.borrow_mut(j) = sum;
    }));
    let two_16 = scalar_from_u64(1 << 16);
    let lo = fold(&cs[0], &cs[1], &two_16);
    let hi = fold(&cs[2], &cs[3], &two_16);
    fold(&lo, &hi, &scalar_from_u64(1 << 32))
}

/// This amount's two u32-limb ciphertexts (`Ǎ_l = C_{2l} + 2^16 C_{2l+1}`) — the shared,
/// key-independent components an auditor pairs with its own decryption handles.
public(package) fun ciphertexts_u32(self: &InRangeVerifiedEncryptedAmount): vector<Element<G>> {
    self.amount.collapse_to_u32().map!(|e| *e.ciphertext())
}

/// `lo + shift * hi`.
fun fold(lo: &Element<G>, hi: &Element<G>, shift: &Element<Scalar>): Element<G> {
    g_add(lo, &g_mul(shift, hi))
}

/// Fold two `Encryption`s into `lo + shift * hi` (ciphertext and handle alike).
fun fold_encryption(lo: &Encryption, hi: &Encryption, shift: &Element<Scalar>): Encryption {
    twisted_elgamal::new(
        fold(lo.ciphertext(), hi.ciphertext(), shift),
        fold(lo.decryption_handle(), hi.decryption_handle(), shift),
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

/// Verify every `commitment` opens to a value in `[0, 2^16)` via one Bulletproof per chunk of
/// `batch_sizes`. An empty `range_proofs` skips the check — only reachable via the `#[test_only]`
/// `assume_range_checked`, since `new_range_proofs` rejects empty input in production.
fun verify_range_proofs(
    commitments: &vector<Element<G>>,
    range_proofs: &vector<vector<u8>>,
    dst: vector<u8>,
): bool {
    if (range_proofs.is_empty()) return true;
    let sizes = batch_sizes(commitments.length());
    if (range_proofs.length() != sizes.length()) return false;
    let mut offset = 0;
    sizes.zip_map_ref!(range_proofs, |chunk, range_proof| {
        let chunk = *chunk;
        let start = offset;
        offset = offset + chunk;
        rangeproofs::verify_bulletproofs_with_dst_ristretto255(
            range_proof,
            LIMB_BITS,
            &vector::tabulate!(chunk, |j| commitments[start + j]),
            &dst,
            BULLETPROOFS_VERSION,
        )
    }).all!(|ok| *ok)
}

/// Canonical Bulletproof chunking for `n` encryptions (one commitment each): greedily take as many
/// `MAX_RANGE_PROOF_BATCH_SIZE` chunks as fit, then halve the chunk size and repeat until `n` is exhausted.
/// Examples (`MAX_RANGE_PROOF_BATCH_SIZE = 32`): n=7 → [4, 2, 1]; n=32 → [32]; n=36 → [32, 4]; n=0 → [].
fun batch_sizes(n: u64): vector<u64> {
    let mut sizes = vector[];
    let mut remaining = n;
    let mut chunk = MAX_RANGE_PROOF_BATCH_SIZE;
    while (remaining > 0) {
        while (remaining >= chunk) {
            sizes.push_back(chunk);
            remaining = remaining - chunk;
        };
        chunk = chunk / 2;
    };
    sizes
}

#[test_only]
use contra::nizk::prove_elgamal;

/// `RangeProofs` that skips the range check — Move tests can't produce Bulletproof bytes, so they
/// assume the range instead of proving it. Not reachable from production (`new_range_proofs` rejects
/// the empty set this holds).
#[test_only]
public fun assume_range_checked(): RangeProofs {
    RangeProofs { proofs: vector[] }
}

/// Collapsed single-`Encryption` view of `ea` — the `public(package)` `collapse` exposed to
/// downstream test packages.
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
public fun consistency_proof_for_testing(
    dst: vector<u8>,
    amount: u16,
    ea: &EncryptedAmount,
    blinding: u64,
    pk: &Element<G>,
): ElGamalProof {
    let e0 = ea[0];
    let e1 = ea[1];
    let e2 = ea[2];
    let e3 = ea[3];
    let b1 = if (*e1.decryption_handle() == g_identity()) 0 else blinding;
    let b2 = if (*e2.decryption_handle() == g_identity()) 0 else blinding;
    let b3 = if (*e3.decryption_handle() == g_identity()) 0 else blinding;
    // Limb messages are (amount, 0, 0, 0); the four share `pk`, so fold them into one proof.
    prove_elgamal(
        dst,
        pk,
        &vector[e0, e1, e2, e3],
        &vector[amount as u64, 0, 0, 0],
        &vector[blinding, b1, b2, b3],
        &scalar_from_u64(1111),
        &scalar_from_u64(2222),
    )
}

#[test_only]
public fun sender_consistency_proof_for_testing(
    dst: vector<u8>,
    new_balance: &EncryptedAmount,
    new_balance_amount: u16,
    new_balance_blinding: u64,
    total: &Encryption,
    total_value: u64,
    total_blinding: u64,
    pk: &Element<G>,
): ElGamalProof {
    let e0 = new_balance[0];
    let e1 = new_balance[1];
    let e2 = new_balance[2];
    let e3 = new_balance[3];
    let b1 = if (*e1.decryption_handle() == g_identity()) 0 else new_balance_blinding;
    let b2 = if (*e2.decryption_handle() == g_identity()) 0 else new_balance_blinding;
    let b3 = if (*e3.decryption_handle() == g_identity()) 0 else new_balance_blinding;
    prove_elgamal(
        dst,
        pk,
        &vector[e0, e1, e2, e3, *total],
        &vector[new_balance_amount as u64, 0, 0, 0, total_value],
        &vector[new_balance_blinding, b1, b2, b3, total_blinding],
        &scalar_from_u64(1111),
        &scalar_from_u64(2222),
    )
}
