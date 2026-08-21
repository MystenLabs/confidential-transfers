// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::encrypted_amount;

use contra::{
    nizk::{DdhProof, ElGamalProof, verify_ddh, verify_elgamal},
    range_proof::RangeProofs,
    twisted_elgamal::{Self, Encryption, PublicKey, g, encrypt_zero}
};
use sui::{group_ops::Element, ristretto255::{G, Scalar, g_add, g_mul, scalar_from_u64}};

#[test_only]
use sui::ristretto255::g_identity;

const U16_LIMBS: u64 = 4;

const EIndexOutOfBounds: u64 = 2;
const EMismatchedBatchLength: u64 = 3;
const EEncryptionProofFailed: u64 = 4;
const ERangeProofFailed: u64 = 5;
const EEmptyBatch: u64 = 6;

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
public struct VerifiedAmount has drop {
    amount: EncryptedAmount,
    pk: PublicKey,
}

/// A wrapper around EncryptedAmount that has been verified to have the following properties:
/// 1) The plaintexts for all limbs are at most 2^16.
/// 2) All limbs are valid encryptions with respect to the given public key (in the Proof of Knowledge sense).
public struct RangeVerifiedAmount has drop {
    amount: EncryptedAmount,
    pk: PublicKey,
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
): VerifiedAmount {
    assert!(proof.verify_elgamal(dst, &pk, &amount.limbs()), EEncryptionProofFailed);
    VerifiedAmount { amount, pk }
}

/// Verify `amount`'s four limbs together with the extra `encryption` under `pk` in one folded proof,
/// returning the amount and the extra separately.
public(package) fun verify_encrypted_amount_and_encryption(
    amount: EncryptedAmount,
    encryption: Encryption,
    pk: PublicKey,
    proof: &ElGamalProof,
    dst: vector<u8>,
): (VerifiedAmount, VerifiedEncryption) {
    let mut ciphertexts = amount.limbs();
    ciphertexts.push_back(encryption);
    assert!(proof.verify_elgamal(dst, &pk, &ciphertexts), EEncryptionProofFailed);
    (VerifiedAmount { amount, pk }, VerifiedEncryption { encryption, pk })
}

/// Range-check every limb of `amounts` (each committed value to `[0, 2^16)`) in one batch and
/// promote each to a `RangeVerifiedAmount`. The amounts are returned in input order.
public(package) fun verify_in_range(
    amounts: vector<VerifiedAmount>,
    range_proofs: RangeProofs,
    dst: vector<u8>,
): vector<RangeVerifiedAmount> {
    // Collect every limb commitment for the single batched range proof.
    let mut commitments = vector<Element<G>>[];
    amounts.do_ref!(|a| U16_LIMBS.do!(|i| commitments.push_back(*a.amount[i].ciphertext())));
    assert!(range_proofs.verify(&commitments, dst), ERangeProofFailed);
    amounts.map!(|a| {
        let VerifiedAmount { amount, pk } = a;
        RangeVerifiedAmount { amount, pk }
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
public(package) fun amount(self: &RangeVerifiedAmount): &EncryptedAmount {
    &self.amount
}

/// The public key `self.amount()` is encrypted under.
public(package) fun pk(self: &RangeVerifiedAmount): &PublicKey {
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

/// The limb-wise difference `a - b`.
public(package) fun sub(a: &EncryptedAmount, b: &EncryptedAmount): EncryptedAmount {
    EncryptedAmount {
        l0: a.l0.sub(&b.l0),
        l1: a.l1.sub(&b.l1),
        l2: a.l2.sub(&b.l2),
        l3: a.l3.sub(&b.l3),
    }
}

/// Verify that `residual` is an encryption of zero under the secret key behind `pk`.
public(package) fun verify_zero(
    pk: &PublicKey,
    residual: &Encryption,
    proof: &DdhProof,
    dst: vector<u8>,
): bool {
    proof.verify_ddh(
        dst,
        &vector[g(), *residual.ciphertext()],
        &vector[*pk.as_element(), *residual.decryption_handle()],
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
    assert!(!amounts.is_empty(), EEmptyBatch);
    let mut cs = vector::tabulate!(U16_LIMBS, |j| *amounts[0][j].ciphertext());
    (amounts.length() - 1).do!(|i| {
        let ea = &amounts[i + 1];
        U16_LIMBS.do!(|j| {
            let sum = g_add(&cs[j], ea[j].ciphertext());
            *cs.borrow_mut(j) = sum;
        });
    });
    let two_16 = scalar_from_u64(1 << 16);
    let lo = fold(&cs[0], &cs[1], &two_16);
    let hi = fold(&cs[2], &cs[3], &two_16);
    fold(&lo, &hi, &scalar_from_u64(1 << 32))
}

/// This amount's two u32-limb ciphertexts (`Ǎ_l = C_{2l} + 2^16 C_{2l+1}`) — the shared,
/// key-independent components an auditor pairs with its own decryption handles.
public(package) fun ciphertexts_u32(self: &RangeVerifiedAmount): vector<Element<G>> {
    let ea = &self.amount;
    let two_16 = scalar_from_u64(1 << 16);
    vector[
        fold(ea.l0.ciphertext(), ea.l1.ciphertext(), &two_16),
        fold(ea.l2.ciphertext(), ea.l3.ciphertext(), &two_16),
    ]
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

/// Add the public `value` into `a`, one u16 digit per limb.
public(package) fun add_assign_value(a: &mut EncryptedAmount, value: u64) {
    a.l0.add_assign_u64(value & 0xFFFF);
    a.l1.add_assign_u64((value >> 16) & 0xFFFF);
    a.l2.add_assign_u64((value >> 32) & 0xFFFF);
    a.l3.add_assign_u64((value >> 48) & 0xFFFF);
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

#[test_only]
use contra::nizk::prove_elgamal;

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
