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
        scalar_from_bytes,
        scalar_from_u64,
        scalar_mul,
    }
};

// Only the `#[test_only]` provers build responses; the on-chain verifiers never add scalars.
#[test_only]
use sui::ristretto255::scalar_add;

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

/// Proves that a shared set of ElGamal commitments `C_k = r_k*g + m_k*h` is consistently encrypted
/// under several public keys `pk_i` — every handle `D_{i,k} = r_k*pk_i` reuses `C_k`'s `(r_k, m_k)`.
/// Folded to `m + 1` points + `2` scalars for `m` keys, versus `m` separate `ElGamalProof`s.
public struct MultiKeyElGamalProof has drop {
    a: vector<Element<G>>,
    b: Element<G>,
    z1: Element<Scalar>,
    z2: Element<Scalar>,
}

public fun new_ddh_proof(commitments: vector<Element<G>>, z: Element<Scalar>): DdhProof {
    DdhProof { commitments, z }
}

public fun new_elgamal_proof(
    a: Element<G>,
    b: Element<G>,
    z1: Element<Scalar>,
    z2: Element<Scalar>,
): ElGamalProof {
    ElGamalProof { a, b, z1, z2 }
}

public fun new_multi_key_elgamal_proof(
    a: vector<Element<G>>,
    b: Element<G>,
    z1: Element<Scalar>,
    z2: Element<Scalar>,
): MultiKeyElGamalProof {
    MultiKeyElGamalProof { a, b, z1, z2 }
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
    if (bases.all!(|b| *b == g_identity())) return false;
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
    let pk = pk.as_element();
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    // Can skip hashing fixed g, h (left as a defense in depth)
    let c = challenge_elgamal(dst, &g, &h, pk, encryptions, &proof.a, &proof.b);

    let mut agg_c = g_identity();
    let mut agg_d = g_identity();
    let mut power = scalar_from_u64(1);
    encryptions.do_ref!(|e| {
        agg_c = g_add(&agg_c, &g_mul(&power, e.ciphertext()));
        agg_d = g_add(&agg_d, &g_mul(&power, e.decryption_handle()));
        power = scalar_mul(&power, &c);
    });

    // Equation 1 (handles): a + c * agg_d == z1 * pk
    // Equation 2 (ciphertexts): b + c * agg_c == z1 * g + z2 * h
    is_valid_relation(&proof.a, &agg_d, pk, &proof.z1, &c) &&
    is_valid_relation2(&proof.b, &agg_c, &g, &h, &proof.z1, &proof.z2, &c)
}

/// Verify a `MultiKeyElGamalProof` over the shared `commitments` `C_k` with `handles_per_key[i][k] =
/// D_{i,k}` (key `i`'s decryption handle for `C_k`). Runs the commitment-side check once and the
/// handle-side check once per key, all under one shared challenge.
public(package) fun verify_multi_key_elgamal(
    proof: &MultiKeyElGamalProof,
    dst: vector<u8>,
    pks: &vector<PublicKey>,
    commitments: &vector<Element<G>>,
    handles_per_key: &vector<vector<Element<G>>>,
): bool {
    let m = pks.length();
    if (m == 0 || commitments.is_empty()) return false;
    if (proof.a.length() != m || handles_per_key.length() != m) return false;
    if (!handles_per_key.all!(|hk| hk.length() == commitments.length())) return false;
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    let pk_elems = pks.map_ref!(|pk| *pk.as_element());
    let c = challenge_multi_key_elgamal(
        dst,
        &g,
        &h,
        &pk_elems,
        commitments,
        handles_per_key,
        &proof.a,
        &proof.b,
    );

    // Commitment side (shared): b + c * sum_k c^k C_k == z1 * g + z2 * h.
    is_valid_relation2(&proof.b, &fold(commitments, &c), &g, &h, &proof.z1, &proof.z2, &c) &&
    // Handle side (per key i): a[i] + c * sum_k c^k D_{i,k} == z1 * pk_i.
    vector::tabulate!(
        m,
        |i| is_valid_relation(&proof.a[i], &fold(&handles_per_key[i], &c), &pk_elems[i], &proof.z1, &c),
    ).all!(|ok| *ok)
}

/// Random linear combination `sum_k c^k * points[k]` with `c^0 = 1`, matching the aggregation the
/// batch challenge folds over.
fun fold(points: &vector<Element<G>>, c: &Element<Scalar>): Element<G> {
    let mut acc = g_identity();
    let mut power = scalar_from_u64(1);
    points.do_ref!(|p| {
        acc = g_add(&acc, &g_mul(&power, p));
        power = scalar_mul(&power, c);
    });
    acc
}

/// Fiat-Shamir challenge for a `DdhProof`. Binds, in order, the DST, every base, every image, and
/// every per-pair Schnorr commitment.
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

/// Fiat-Shamir challenge for a `MultiKeyElGamalProof`. Binds, in order: the DST, the bases `g, h`,
/// every public key `pk_i`, every shared commitment `C_k`, then every key's handles `D_{i,k}`
/// (key-major), then the per-key handle-side masks `a[i]`, then the commitment-side mask `b`.
fun challenge_multi_key_elgamal(
    dst: vector<u8>,
    g: &Element<G>,
    h: &Element<G>,
    pks: &vector<Element<G>>,
    commitments: &vector<Element<G>>,
    handles: &vector<vector<Element<G>>>,
    a: &vector<Element<G>>,
    b: &Element<G>,
): Element<Scalar> {
    let mut inputs = vector[dst, *g.bytes(), *h.bytes()];
    pks.do_ref!(|pk| inputs.push_back(*pk.bytes()));
    commitments.do_ref!(|cm| inputs.push_back(*cm.bytes()));
    handles.do_ref!(|hk| hk.do_ref!(|d| inputs.push_back(*d.bytes())));
    a.do_ref!(|ai| inputs.push_back(*ai.bytes()));
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

#[test]
fun fiat_shamir_challenge_regression() {
    let dst = vector::tabulate!(21, |i| i as u8);
    let p1 = vector::tabulate!(32, |i| i as u8);
    let c = fiat_shamir_challenge(vector[dst, p1]);
    assert!(*c.bytes() == x"af00c4976049ed81805c76d3c5ba7cfaeb1550e44f5978cffb12b285a5e25a00");
}

#[test_only]
public fun prove_ddh(
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

#[test_only]
public fun prove_elgamal(
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
public fun default_elgamal_proof(): ElGamalProof {
    ElGamalProof {
        a: g_identity(),
        b: g_identity(),
        z1: scalar_from_u64(0),
        z2: scalar_from_u64(0),
    }
}

#[test_only]
public fun default_multi_key_elgamal_proof(): MultiKeyElGamalProof {
    MultiKeyElGamalProof {
        a: vector[],
        b: g_identity(),
        z1: scalar_from_u64(0),
        z2: scalar_from_u64(0),
    }
}

/// Prove a `MultiKeyElGamalProof` for `pks` over the shared commitments `C_k = r_k*g + m_k*h`
/// (`commitments`) with `handles_per_key[i][k] = r_k*pk_i`. `messages` are the `m_k` and `blindings`
/// the `r_k` (length `K`, shared across keys); `(ma, mb)` are the masks.
#[test_only]
public fun prove_multi_key_elgamal(
    dst: vector<u8>,
    pks: &vector<Element<G>>,
    commitments: &vector<Element<G>>,
    handles_per_key: &vector<vector<Element<G>>>,
    messages: &vector<u64>,
    blindings: &vector<u64>,
    ma: &Element<Scalar>,
    mb: &Element<Scalar>,
): MultiKeyElGamalProof {
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    let a = pks.map_ref!(|pk| g_mul(ma, pk));
    let b = g_add(&g_mul(ma, &g), &g_mul(mb, &h));
    let c = challenge_multi_key_elgamal(dst, &g, &h, pks, commitments, handles_per_key, &a, &b);
    // z1 = ma + sum_k c^{k+1} r_k ; z2 = mb + sum_k c^{k+1} m_k, with c^j starting at c^1.
    let mut z1 = *ma;
    let mut z2 = *mb;
    let mut power = c;
    messages.length().do!(|k| {
        z1 = scalar_add(&z1, &scalar_mul(&power, &scalar_from_u64(blindings[k])));
        z2 = scalar_add(&z2, &scalar_mul(&power, &scalar_from_u64(messages[k])));
        power = scalar_mul(&power, &c);
    });
    MultiKeyElGamalProof { a, b, z1, z2 }
}

#[test]
fun multi_key_elgamal_round_trip() {
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    // Three keys share four commitments `C_k = r_k*g + m_k*h`; key i's handles are `r_k*pk_i`.
    let sks = vector[scalar_from_u64(111), scalar_from_u64(222), scalar_from_u64(333)];
    let pks = sks.map_ref!(|sk| g_mul(sk, &g));
    let messages = vector[7u64, 0, 65535, 42];
    let blindings = vector[11u64, 22, 33, 44];
    let commitments = messages.zip_map_ref!(
        &blindings,
        |m, r| g_add(&g_mul(&scalar_from_u64(*r), &g), &g_mul(&scalar_from_u64(*m), &h)),
    );
    let handles_per_key = pks.map_ref!(
        |pk| blindings.map_ref!(|r| g_mul(&scalar_from_u64(*r), pk)),
    );
    let proof = prove_multi_key_elgamal(
        vector[],
        &pks,
        &commitments,
        &handles_per_key,
        &messages,
        &blindings,
        &scalar_from_u64(24680),
        &scalar_from_u64(13579),
    );
    let pk_keys = pks.map_ref!(|pk| twisted_elgamal::public_key(*pk));
    assert!(verify_multi_key_elgamal(&proof, vector[], &pk_keys, &commitments, &handles_per_key));

    // Tampering with any key's handle breaks verification (the challenge binds every handle).
    let mut bad = handles_per_key;
    *bad.borrow_mut(1).borrow_mut(0) = g_mul(&scalar_from_u64(999), &pks[1]);
    assert!(!verify_multi_key_elgamal(&proof, vector[], &pk_keys, &commitments, &bad));

    // A statement with the wrong number of keys fails the length check.
    let mut short = pk_keys;
    short.pop_back();
    assert!(!verify_multi_key_elgamal(&proof, vector[], &short, &commitments, &handles_per_key));
}

/// Build a DDH proof of knowledge of `sk` such that `ea.ciphertext - amount*h = sk*g` and
/// `ea.decryption_handle = sk*pk` — i.e. that `ea` decrypts to `amount` under `sk` (where
/// `pk = sk*g`).
#[test_only]
public fun value_proof_for_testing(
    dst: vector<u8>,
    amount: u64,
    ea: &Encryption,
    sk: &Element<Scalar>,
): DdhProof {
    let g = twisted_elgamal::g();
    let pk = g_mul(sk, &g);
    let commitment_to_zero = ristretto255::g_sub(
        ea.ciphertext(),
        &g_mul(&scalar_from_u64(amount), &twisted_elgamal::h()),
    );
    prove_ddh(
        dst,
        sk,
        &vector[g, commitment_to_zero],
        &vector[pk, *ea.decryption_handle()],
        &scalar_from_u64(1234), // randomness
    )
}

/// Like `value_proof_for_testing` but for `amount = 0` — proves `ea.ciphertext = sk*g` and
/// `ea.decryption_handle = sk*pk`, i.e. `ea` decrypts to zero under `sk`.
#[test_only]
public fun zero_proof_for_testing(
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

/// Pin the Fiat-Shamir transcript layout of both proof types (not just the hash primitive, which
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
}
