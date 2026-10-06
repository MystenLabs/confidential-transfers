// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::nizk;

use contra::twisted_elgamal::{Self, Encryption, PublicKey};
use std::bcs;
use sui::{
    group_ops::Element,
    ristretto255::{
        Self,
        G,
        Scalar,
        g_add,
        g_identity,
        g_mul,
        g_sub,
        scalar_from_bytes,
        scalar_from_u64,
        scalar_mul,
    }
};

// === Errors ===

/// `verify_elgamal`: an empty batch is a vacuous statement, so it is never a valid one to verify.
const EEmptyBatch: u64 = 0;

// === Structs ===

/// A shared-witness DDH proof of knowledge: one `w` with `images[k] = w * bases[k]` for all `k`.
public struct DdhProof has drop {
    commitments: vector<Element<G>>,
    z: Element<Scalar>,
}

/// A witness-folded batch of ElGamal proofs over ciphertexts sharing one public key `pk`.
/// Proves that for every ciphertext `(C_j, D_j)` the prover knows `(r_j, m_j)` with
/// `C_j = r_j*g + m_j*h` and `D_j = r_j*pk`.
public struct ElGamalProof has drop {
    a: Element<G>,
    b: Element<G>,
    z1: Element<Scalar>,
    z2: Element<Scalar>,
}

/// A proof of knowledge of the old and new secret keys `(x, x')` of a key rotation, with
/// `old_pk = x*g`, `new_pk = x'*g` and `x'*old_handles[i] == x*new_handles[i]` for every limb `i`.
/// Since `d = r*pk`, the last relation says `new_handles[i] = (x'/x) * old_handles[i]`: each handle
/// is re-keyed from `old_pk` to `new_pk`. Proving knowledge of `x` (not just of the ratio `x'/x`,
/// which anyone can pick) is what stops a party holding only the account's `Auth`, but not its
/// secret key, from rotating the balance to a key nobody can decrypt under.
public struct RekeyProof has drop {
    a_old: Element<G>,
    a_new: Element<G>,
    a_handles: Element<G>,
    z_old: Element<Scalar>,
    z_new: Element<Scalar>,
}

public fun new_ddh_proof(commitments: vector<Element<G>>, z: Element<Scalar>): DdhProof {
    DdhProof { commitments, z }
}

public fun new_rekey_proof(
    a_old: Element<G>,
    a_new: Element<G>,
    a_handles: Element<G>,
    z_old: Element<Scalar>,
    z_new: Element<Scalar>,
): RekeyProof {
    RekeyProof { a_old, a_new, a_handles, z_old, z_new }
}

public fun new_elgamal_proof(
    a: Element<G>,
    b: Element<G>,
    z1: Element<Scalar>,
    z2: Element<Scalar>,
): ElGamalProof {
    ElGamalProof { a, b, z1, z2 }
}

/// Verify a `DdhProof`: a single witness `w` maps every base to its image,
/// `images[k] == w * bases[k]` for all `k`.
public(package) fun verify_ddh(
    proof: &DdhProof,
    dst: vector<u8>,
    bases: &vector<Element<G>>,
    images: &vector<Element<G>>,
): bool {
    let n = bases.length();
    if (images.length() != n || proof.commitments.length() != n) return false;
    // Hoisted: `g_identity()` is a native call, and the closure would rebuild it per base.
    let identity = g_identity();
    if (bases.all!(|b| *b == identity)) return false;
    let c = challenge_ddh(dst, bases, images, &proof.commitments);
    vector::tabulate!(
        n,
        |k| is_valid_relation(&proof.commitments[k], &images[k], &bases[k], &proof.z, &c),
    ).all!(|b| *b)
}

/// Verify that the prover knows `(r_j, m_j)` for every ciphertext `(C_j, D_j)` in the batch.
public(package) fun verify_elgamal(
    proof: &ElGamalProof,
    dst: vector<u8>,
    pk: &PublicKey,
    encryptions: &vector<Encryption>,
): bool {
    let n = encryptions.length();
    assert!(n > 0, EEmptyBatch);

    let pk = pk.as_element();
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    // Can skip hashing fixed g, h (left as a defense in depth)
    let c = challenge_elgamal(dst, &g, &h, pk, encryptions, &proof.a, &proof.b);

    let mut agg_c = *encryptions[0].ciphertext();
    let mut agg_d = *encryptions[0].decryption_handle();
    let mut power = c;
    (n - 1).do!(|k| {
        let e = &encryptions[k + 1];
        agg_c = g_add(&agg_c, &g_mul(&power, e.ciphertext()));
        agg_d = g_add(&agg_d, &g_mul(&power, e.decryption_handle()));
        power = scalar_mul(&power, &c);
    });

    // Equation 1 (handles): a + c * agg_d == z1 * pk
    // Equation 2 (ciphertexts): b + c * agg_c == z1 * g + z2 * h
    is_valid_relation(&proof.a, &agg_d, pk, &proof.z1, &c) &&
    is_valid_relation2(&proof.b, &agg_c, &g, &h, &proof.z1, &proof.z2, &c)
}

/// Verify a `RekeyProof` that `new_handles` re-key `old_handles` from `old_pk` to `new_pk`, and that
/// the prover knows both secret keys.
public(package) fun verify_rekey(
    proof: &RekeyProof,
    dst: vector<u8>,
    old_pk: &PublicKey,
    new_pk: &PublicKey,
    old_handles: &vector<Element<G>>,
    new_handles: &vector<Element<G>>,
): bool {
    let n = old_handles.length();
    if (new_handles.length() != n) return false;
    let g = twisted_elgamal::g();
    let old_pk = old_pk.as_element();
    let new_pk = new_pk.as_element();

    // The handle rows `x'*d_i - x*d'_i = 0` are homogeneous, so they fold into one row with powers
    // of `rho`. `rho` must be drawn from the statement alone: `a_handles` is computed from the
    // folded handles, so it cannot also feed the challenge the weights come from.
    let rho = challenge_rekey_weights(dst, &g, old_pk, new_pk, old_handles, new_handles);
    let mut agg_old = g_identity();
    let mut agg_new = g_identity();
    let mut power = scalar_from_u64(1);
    n.do!(|i| {
        agg_old = g_add(&agg_old, &g_mul(&power, &old_handles[i]));
        agg_new = g_add(&agg_new, &g_mul(&power, &new_handles[i]));
        power = scalar_mul(&power, &rho);
    });

    let c = challenge_rekey(dst, &rho, &proof.a_old, &proof.a_new, &proof.a_handles);

    // a_old + c * old_pk == z_old * g
    // a_new + c * new_pk == z_new * g
    // a_handles == z_new * agg_old - z_old * agg_new
    is_valid_relation(&proof.a_old, old_pk, &g, &proof.z_old, &c) &&
    is_valid_relation(&proof.a_new, new_pk, &g, &proof.z_new, &c) &&
    proof.a_handles == g_sub(&g_mul(&proof.z_new, &agg_old), &g_mul(&proof.z_old, &agg_new))
}

/// Folding weight for a `RekeyProof`'s handle rows. Binds, in order, the DST, `g`, both public keys,
/// every old handle and every new handle.
fun challenge_rekey_weights(
    dst: vector<u8>,
    g: &Element<G>,
    old_pk: &Element<G>,
    new_pk: &Element<G>,
    old_handles: &vector<Element<G>>,
    new_handles: &vector<Element<G>>,
): Element<Scalar> {
    let mut inputs = vector[dst, *g.bytes(), *old_pk.bytes(), *new_pk.bytes()];
    old_handles.do_ref!(|d| inputs.push_back(*d.bytes()));
    new_handles.do_ref!(|d| inputs.push_back(*d.bytes()));
    fiat_shamir_challenge(inputs)
}

/// Fiat-Shamir challenge for a `RekeyProof`. Binds, in order, the DST, the folding weight `rho`
/// (which already binds the whole statement), and the three commitments.
fun challenge_rekey(
    dst: vector<u8>,
    rho: &Element<Scalar>,
    a_old: &Element<G>,
    a_new: &Element<G>,
    a_handles: &Element<G>,
): Element<Scalar> {
    fiat_shamir_challenge(vector[
        dst,
        *rho.bytes(),
        *a_old.bytes(),
        *a_new.bytes(),
        *a_handles.bytes(),
    ])
}

/// Fiat-Shamir challenge for a `DdhProof`. Binds, in order, the DST, every base, every image, and
/// every per-pair Schnorr commitment. Unlike `challenge_elgamal`, `g`/`h` are not hashed: a DDH
/// statement carries its bases explicitly, so they play no implicit role here.
fun challenge_ddh(
    dst: vector<u8>,
    bases: &vector<Element<G>>,
    images: &vector<Element<G>>,
    commitments: &vector<Element<G>>,
): Element<Scalar> {
    let mut inputs = vector[dst];
    bases.do_ref!(|b| inputs.push_back(*b.bytes()));
    images.do_ref!(|i| inputs.push_back(*i.bytes()));
    commitments.do_ref!(|cm| inputs.push_back(*cm.bytes()));
    fiat_shamir_challenge(inputs)
}

/// Fiat-Shamir challenge for an `ElGamalProof`. Binds, in order, the DST, the bases `g, h`, the
/// shared public key, every ciphertext `(C_j, D_j)`, and the two mask commitments `(a, b)`.
/// Drawing `c` after committing to the whole statement is what stops the prover from choosing a
/// batch the aggregate would mask.
fun challenge_elgamal(
    dst: vector<u8>,
    g: &Element<G>,
    h: &Element<G>,
    pk: &Element<G>,
    encryptions: &vector<Encryption>,
    a: &Element<G>,
    b: &Element<G>,
): Element<Scalar> {
    let mut inputs = vector[dst, *g.bytes(), *h.bytes(), *pk.bytes()];
    encryptions.do_ref!(|e| {
        inputs.push_back(*e.ciphertext().bytes());
        inputs.push_back(*e.decryption_handle().bytes());
    });
    inputs.push_back(*a.bytes());
    inputs.push_back(*b.bytes());
    fiat_shamir_challenge(inputs)
}

fun fiat_shamir_challenge(random_oracle_inputs: vector<vector<u8>>): Element<Scalar> {
    let mut hash = sui::hash::blake2b256(&bcs::to_bytes(&random_oracle_inputs));
    // Clearing the top byte ensures the challenge is below the group order.
    // Fiat-Shamir only requires a large domain.
    *vector::borrow_mut(&mut hash, 31) = 0;
    scalar_from_bytes(&hash)
}

/// Checks the one-response Schnorr row: `e1 + c * e2 == z * e3`.
fun is_valid_relation(
    e1: &Element<G>,
    e2: &Element<G>,
    e3: &Element<G>,
    z: &Element<Scalar>,
    c: &Element<Scalar>,
): bool {
    g_add(e1, &g_mul(c, e2)) == g_mul(z, e3)
}

/// Checks the two-response Schnorr row: `e1 + c * e2 == z1 * b1 + z2 * b2`.
fun is_valid_relation2(
    e1: &Element<G>,
    e2: &Element<G>,
    b1: &Element<G>,
    b2: &Element<G>,
    z1: &Element<Scalar>,
    z2: &Element<Scalar>,
    c: &Element<Scalar>,
): bool {
    g_add(e1, &g_mul(c, e2)) == g_add(&g_mul(z1, b1), &g_mul(z2, b2))
}

// === Test Helpers ===

#[test_only]
use sui::ristretto255::scalar_add;

#[test]
fun fiat_shamir_challenge_regression() {
    let dst = vector::tabulate!(21, |i| i as u8);
    let p1 = vector::tabulate!(32, |i| i as u8);
    let c = fiat_shamir_challenge(vector[dst, p1]);
    assert!(*c.bytes() == x"af00c4976049ed81805c76d3c5ba7cfaeb1550e44f5978cffb12b285a5e25a00");
}

#[test_only]
public(package) fun prove_ddh(
    dst: vector<u8>,
    w: &Element<Scalar>,
    bases: &vector<Element<G>>,
    images: &vector<Element<G>>,
    s: &Element<Scalar>,
): DdhProof {
    let commitments = bases.map_ref!(|b| g_mul(s, b));
    let c = challenge_ddh(dst, bases, images, &commitments);
    let z = scalar_add(s, &scalar_mul(&c, w));
    DdhProof { commitments, z }
}

#[test_only]
public fun default_ddh_proof(): DdhProof {
    DdhProof { commitments: vector[], z: scalar_from_u64(0) }
}

/// Build a `RekeyProof` for rotating `old_handles` from `old_sk` to `new_sk`, with masks `(s_old,
/// s_new)`.
#[test_only]
public(package) fun prove_rekey(
    dst: vector<u8>,
    old_sk: &Element<Scalar>,
    new_sk: &Element<Scalar>,
    old_handles: &vector<Element<G>>,
    new_handles: &vector<Element<G>>,
    s_old: &Element<Scalar>,
    s_new: &Element<Scalar>,
): RekeyProof {
    let g = twisted_elgamal::g();
    let old_pk = g_mul(old_sk, &g);
    let new_pk = g_mul(new_sk, &g);
    let rho = challenge_rekey_weights(dst, &g, &old_pk, &new_pk, old_handles, new_handles);
    let mut agg_old = g_identity();
    let mut agg_new = g_identity();
    let mut power = scalar_from_u64(1);
    old_handles.length().do!(|i| {
        agg_old = g_add(&agg_old, &g_mul(&power, &old_handles[i]));
        agg_new = g_add(&agg_new, &g_mul(&power, &new_handles[i]));
        power = scalar_mul(&power, &rho);
    });
    let a_old = g_mul(s_old, &g);
    let a_new = g_mul(s_new, &g);
    let a_handles = g_sub(&g_mul(s_new, &agg_old), &g_mul(s_old, &agg_new));
    let c = challenge_rekey(dst, &rho, &a_old, &a_new, &a_handles);
    RekeyProof {
        a_old,
        a_new,
        a_handles,
        z_old: scalar_add(s_old, &scalar_mul(&c, old_sk)),
        z_new: scalar_add(s_new, &scalar_mul(&c, new_sk)),
    }
}

#[test_only]
public(package) fun prove_elgamal(
    dst: vector<u8>,
    pk: &Element<G>,
    encryptions: &vector<Encryption>,
    messages: &vector<u64>,
    blindings: &vector<u64>,
    ma: &Element<Scalar>,
    mb: &Element<Scalar>,
): ElGamalProof {
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    // a = ma*pk (handle side); b = ma*g + mb*h (ciphertext side).
    let a = g_mul(ma, pk);
    let b = g_add(&g_mul(ma, &g), &g_mul(mb, &h));
    let c = challenge_elgamal(dst, &g, &h, pk, encryptions, &a, &b);
    // z1 = ma + sum_j c^j r_j ; z2 = mb + sum_j c^j m_j, with c^j starting at c^1.
    let mut z1 = *ma;
    let mut z2 = *mb;
    let mut power = c;
    encryptions.length().do!(|j| {
        z1 = scalar_add(&z1, &scalar_mul(&power, &scalar_from_u64(blindings[j])));
        z2 = scalar_add(&z2, &scalar_mul(&power, &scalar_from_u64(messages[j])));
        power = scalar_mul(&power, &c);
    });
    ElGamalProof { a, b, z1, z2 }
}

#[test_only]
public(package) fun default_elgamal_proof(): ElGamalProof {
    ElGamalProof {
        a: g_identity(),
        b: g_identity(),
        z1: scalar_from_u64(0),
        z2: scalar_from_u64(0),
    }
}

/// Build a DDH proof that `ea` decrypts to zero under `sk` (where `pk = sk*g`):
/// `ea.ciphertext = w*g` and `ea.decryption_handle = w*pk` for the shared witness.
#[test_only]
public(package) fun zero_proof_for_testing(
    dst: vector<u8>,
    ea: &Encryption,
    sk: &Element<Scalar>,
): DdhProof {
    let g = twisted_elgamal::g();
    let pk = g_mul(sk, &g);
    prove_ddh(
        dst,
        sk,
        &vector[g, *ea.ciphertext()],
        &vector[pk, *ea.decryption_handle()],
        &scalar_from_u64(12345), // randomness
    )
}

/// Build a DDH proof that `sum` is the homomorphic sum of `a` and `b` under `sk` (where
/// `pk = sk*g`) — i.e. `(a + b - sum)` is an encryption of zero under `sk`.
#[test_only]
public fun sum_proof_for_testing(
    dst: vector<u8>,
    sum: &Encryption,
    a: &Encryption,
    b: &Encryption,
    sk: &Element<Scalar>,
): DdhProof {
    let g = twisted_elgamal::g();
    let pk = g_mul(sk, &g);
    let zero_encryption = a.add(b).sub(sum);
    prove_ddh(
        dst,
        sk,
        &vector[g, *zero_encryption.ciphertext()],
        &vector[pk, *zero_encryption.decryption_handle()],
        &scalar_from_u64(1234567), // randomness
    )
}

#[test]
fun ddh_proof_round_trip() {
    let g = ristretto255::g_generator();
    let tuple1 = g_mul(&scalar_from_u64(3), &g);
    let tuple2 = g_mul(&scalar_from_u64(4), &g);
    let tuple3 = g_mul(&scalar_from_u64(12), &g);

    let bases = vector[g, tuple1];
    let images = vector[tuple2, tuple3];
    let proof = prove_ddh(
        vector[],
        &scalar_from_u64(4),
        &bases,
        &images,
        &scalar_from_u64(91011), // randomness
    );

    assert!(verify_ddh(&proof, vector[], &bases, &images));
}

#[test]
fun ddh_proof_batch_round_trip() {
    let g = ristretto255::g_generator();
    let w = scalar_from_u64(13579);
    // Five independent bases; images are each `w * base`.
    let bases = vector::tabulate!(5, |i| g_mul(&scalar_from_u64((i + 1) * 100), &g));
    let images = bases.map_ref!(|b| g_mul(&w, b));
    let proof = prove_ddh(vector[], &w, &bases, &images, &scalar_from_u64(24680));
    assert!(verify_ddh(&proof, vector[], &bases, &images));

    // A wrong image breaks verification.
    let mut bad_images = images;
    *bad_images.borrow_mut(2) = g;
    assert!(!verify_ddh(&proof, vector[], &bases, &bad_images));

    // A statement shorter than the proof's commitment vector fails the length check (returns
    // false, no abort).
    let mut short_bases = bases;
    short_bases.pop_back();
    let mut short_images = images;
    short_images.pop_back();
    assert!(!verify_ddh(&proof, vector[], &short_bases, &short_images));
}

/// A statement whose every base is the identity binds no witness and is rejected outright, even
/// with a proof honestly built for it.
#[test]
fun ddh_proof_rejects_all_identity_bases() {
    let id = g_identity();
    let bases = vector[id, id];
    let images = vector[id, id];
    let proof = prove_ddh(vector[], &scalar_from_u64(7), &bases, &images, &scalar_from_u64(99));
    assert!(!verify_ddh(&proof, vector[], &bases, &images));
}

/// A single identity base (e.g. a zero-blinding decryption handle) is allowed as long as some other
/// base binds the witness — this mirrors re-keying a pristine balance.
#[test]
fun ddh_proof_allows_individual_identity_base() {
    let g = ristretto255::g_generator();
    let w = scalar_from_u64(13);
    let bases = vector[g, g_identity()];
    let images = vector[g_mul(&w, &g), g_identity()];
    let proof = prove_ddh(vector[], &w, &bases, &images, &scalar_from_u64(42));
    assert!(verify_ddh(&proof, vector[], &bases, &images));
}

#[test_only]
fun rekey_statement_for_testing(
    old_sk: &Element<Scalar>,
    new_sk: &Element<Scalar>,
): (PublicKey, PublicKey, vector<Element<G>>, vector<Element<G>>) {
    let g = twisted_elgamal::g();
    let old_pk = g_mul(old_sk, &g);
    let new_pk = g_mul(new_sk, &g);
    // Four limb handles `r_i * pk`; the last limb has zero blinding (identity handle), as in a
    // pristine balance.
    let rs = vector[111u64, 222, 333, 0];
    let old_handles = rs.map_ref!(|r| g_mul(&scalar_from_u64(*r), &old_pk));
    let new_handles = rs.map_ref!(|r| g_mul(&scalar_from_u64(*r), &new_pk));
    (
        twisted_elgamal::public_key(old_pk),
        twisted_elgamal::public_key(new_pk),
        old_handles,
        new_handles,
    )
}

#[test]
fun rekey_proof_round_trip() {
    let old_sk = scalar_from_u64(11111);
    let new_sk = scalar_from_u64(22222);
    let (old_pk, new_pk, old_handles, new_handles) = rekey_statement_for_testing(&old_sk, &new_sk);
    let proof = prove_rekey(
        vector[],
        &old_sk,
        &new_sk,
        &old_handles,
        &new_handles,
        &scalar_from_u64(31415),
        &scalar_from_u64(92653),
    );
    assert!(verify_rekey(&proof, vector[], &old_pk, &new_pk, &old_handles, &new_handles));

    // A different DST breaks verification.
    assert!(!verify_rekey(&proof, vector[1], &old_pk, &new_pk, &old_handles, &new_handles));

    // A tampered new handle breaks verification.
    let mut bad_handles = new_handles;
    *bad_handles.borrow_mut(1) = twisted_elgamal::g();
    assert!(!verify_rekey(&proof, vector[], &old_pk, &new_pk, &old_handles, &bad_handles));

    // Mismatched handle counts are rejected (returns false, no abort).
    let mut short_handles = new_handles;
    short_handles.pop_back();
    assert!(!verify_rekey(&proof, vector[], &old_pk, &new_pk, &old_handles, &short_handles));
}

/// Without the old secret key, a valid re-key cannot be proven: anyone can pick a ratio `w` and
/// publish `new_pk = w*old_pk`, `new_handles = w*old_handles` (a correct re-keying to a key whose
/// secret `w*x` nobody knows), but the proof also needs `x` itself.
#[test]
fun rekey_proof_requires_old_secret_key() {
    let old_sk = scalar_from_u64(11111);
    let w = scalar_from_u64(7);
    let new_sk = scalar_mul(&w, &old_sk);
    let (old_pk, new_pk, old_handles, new_handles) = rekey_statement_for_testing(&old_sk, &new_sk);
    // The honest proof verifies, so the statement itself is a valid re-keying.
    let honest = prove_rekey(
        vector[],
        &old_sk,
        &new_sk,
        &old_handles,
        &new_handles,
        &scalar_from_u64(1),
        &scalar_from_u64(2),
    );
    assert!(verify_rekey(&honest, vector[], &old_pk, &new_pk, &old_handles, &new_handles));

    // An attacker knowing only `w` cannot produce one.
    let forged = prove_rekey(
        vector[],
        &scalar_from_u64(1),
        &w,
        &old_handles,
        &new_handles,
        &scalar_from_u64(1),
        &scalar_from_u64(2),
    );
    assert!(!verify_rekey(&forged, vector[], &old_pk, &new_pk, &old_handles, &new_handles));
}

#[test]
fun elgamal_proof_round_trip() {
    // Batch-of-1: the classic single-ciphertext well-formedness proof.
    let pk = g_mul(&scalar_from_u64(12345), &twisted_elgamal::g());
    let encryptions = vector[twisted_elgamal::encrypt_trivial_for_testing(42, &pk, 67890)];
    let proof = prove_elgamal(
        vector[],
        &pk,
        &encryptions,
        &vector[42],
        &vector[67890],
        &scalar_from_u64(1234),
        &scalar_from_u64(5678),
    );
    assert!(verify_elgamal(&proof, vector[], &twisted_elgamal::public_key(pk), &encryptions));
}

#[test]
fun elgamal_proof_batch_round_trip() {
    let pk = g_mul(&scalar_from_u64(12345), &twisted_elgamal::g());
    // Five same-key ciphertexts (C_j, D_j) = (r_j*g + m_j*h, r_j*pk).
    let messages = vector[7u64, 0, 65535, 42, 1];
    let blindings = vector[111u64, 222, 333, 444, 555];
    let encryptions = messages.zip_map_ref!(
        &blindings,
        |m, r| twisted_elgamal::encrypt_trivial_for_testing(*m, &pk, *r),
    );

    let proof = prove_elgamal(
        vector[],
        &pk,
        &encryptions,
        &messages,
        &blindings,
        &scalar_from_u64(24680),
        &scalar_from_u64(13579),
    );
    assert!(verify_elgamal(&proof, vector[], &twisted_elgamal::public_key(pk), &encryptions));

    // Tampering with any ciphertext breaks verification.
    let mut bad = encryptions;
    *bad.borrow_mut(2) = twisted_elgamal::encrypt_trivial_for_testing(1, &pk, 333);
    assert!(!verify_elgamal(&proof, vector[], &twisted_elgamal::public_key(pk), &bad));

    // A different key breaks verification.
    let other_pk = g_mul(&scalar_from_u64(99999), &twisted_elgamal::g());
    assert!(
        !verify_elgamal(&proof, vector[], &twisted_elgamal::public_key(other_pk), &encryptions),
    );
}

/// The challenge binds the whole batch, so a proof cannot be replayed against any other statement
/// built from the same ciphertexts — shorter, longer, or reordered.
#[test]
fun elgamal_proof_statement_substitution_fails() {
    let pk = g_mul(&scalar_from_u64(12345), &twisted_elgamal::g());
    let messages = vector[7u64, 0, 65535, 42, 1];
    let blindings = vector[111u64, 222, 333, 444, 555];
    let encryptions = messages.zip_map_ref!(
        &blindings,
        |m, r| twisted_elgamal::encrypt_trivial_for_testing(*m, &pk, *r),
    );
    let proof = prove_elgamal(
        vector[],
        &pk,
        &encryptions,
        &messages,
        &blindings,
        &scalar_from_u64(24680),
        &scalar_from_u64(13579),
    );

    // A prefix of the proven batch.
    let mut prefix = encryptions;
    prefix.pop_back();
    assert!(!verify_elgamal(&proof, vector[], &twisted_elgamal::public_key(pk), &prefix));

    // The proven batch extended by one more valid ciphertext.
    let mut extended = encryptions;
    extended.push_back(twisted_elgamal::encrypt_trivial_for_testing(9, &pk, 666));
    assert!(!verify_elgamal(&proof, vector[], &twisted_elgamal::public_key(pk), &extended));

    // The proven ciphertexts in a different order.
    let mut swapped = encryptions;
    swapped.swap(0, 1);
    assert!(!verify_elgamal(&proof, vector[], &twisted_elgamal::public_key(pk), &swapped));
}

/// Pin the Fiat-Shamir transcript layout of every proof type (not just the hash primitive, which
/// `fiat_shamir_challenge_regression` covers). Round-trip tests can't catch the prover and
/// verifier drifting together; this locks the byte layout client-side provers must reproduce.
#[test]
fun challenge_transcript_regression() {
    let dst = vector::tabulate!(21, |i| i as u8);
    let g = ristretto255::g_generator();
    let points = vector::tabulate!(6, |i| g_mul(&scalar_from_u64((i + 1) * 11), &g));

    let c_ddh = challenge_ddh(
        dst,
        &vector[points[0], points[1]],
        &vector[points[2], points[3]],
        &vector[points[4], points[5]],
    );
    assert!(*c_ddh.bytes() == x"b5baa7c858c0eb740d9c38cc273f2062998dad57a798fa00e78cc33b4ba54200");

    let encryptions = vector[
        twisted_elgamal::new(points[0], points[1]),
        twisted_elgamal::new(points[2], points[3]),
    ];
    let c_eg = challenge_elgamal(
        dst,
        &twisted_elgamal::g(),
        &twisted_elgamal::h(),
        &points[4], // pk
        &encryptions,
        &points[5], // a
        &points[0], // b
    );
    assert!(*c_eg.bytes() == x"bfc70a5eb7a3d6ff45c7f259078b46d3d1a1cd1c8f9affe06b3d37bb40548900");

    let rho = challenge_rekey_weights(
        dst,
        &twisted_elgamal::g(),
        &points[0], // old_pk
        &points[1], // new_pk
        &vector[points[2], points[3]],
        &vector[points[4], points[5]],
    );
    assert!(*rho.bytes() == x"4d82c8e67d9dbbf2f726e15318e050a3cad9f4db8b66a4015abba44ef522bc00");
    let c_rekey = challenge_rekey(dst, &rho, &points[0], &points[1], &points[2]);
    assert!(
        *c_rekey.bytes() == x"54ba91d11bcd695874204d32a8ad13bbc0c804b2e5cbd28021b6f9dad0977500",
    );
}
