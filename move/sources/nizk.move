// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::nizk;

use contra::twisted_elgamal::{Self, Encryption, MultiRecipientEncryption};
use std::bcs;
use sui::{
    group_ops::Element,
    hash,
    ristretto255::{
        Self,
        G,
        Scalar,
        g_add,
        g_identity,
        g_mul,
        scalar_add,
        scalar_from_bytes,
        scalar_from_u64,
        scalar_mul
    }
};

/// Number of 32-bit limbs in a `KeyConsistencyProof`. A 256-bit Ristretto255 scalar split into
/// 32-bit chunks gives exactly 8 limbs; this is fixed by the protocol, not negotiable per call.
const KEY_CONSISTENCY_LIMBS: u64 = 8;

/// `verify_key_consistency` was called with vectors whose lengths don't match the protocol
/// constants (`KEY_CONSISTENCY_LIMBS` limbs, `recipient_encryption_keys.length()` recipients).
const EMalformedKeyConsistencyProof: u64 = 0;

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

/// A non-interactive zero knowledge proof of knowledge showing that the eight 32-bit limbs of a
/// 256-bit private key are correctly encrypted to a list of m recipient public keys `pk_j` using
/// Twisted ElGamal. The proof shows that the prover knows randomness `(r_1, ..., r_8)` and key
/// limbs `(u_1, ..., u_8)` such that:
/// - `D_ij = r_i * pk_j` for all i and j, where `D_ij` is the decryption handle for the i-th limb
///   and j-th recipient.
/// - `C_i = r_i * g + u_i * h` for all i, where `C_i` is the ciphertext for the i-th limb.
/// - `(\sum_i u_i * 2^{32i}) * g == sender_public_key`.
public struct KeyConsistencyProof has drop {
    a1: vector<Element<G>>, // 8*m elements: a_i * pk_j for all (i, j)
    a2: vector<Element<G>>, // 8 elements: a_i * g + b_i * h
    a3: Element<G>, // Single aggregate mask (\sum_i b_i * 2^{32i}) * g.
    z1: vector<Element<Scalar>>, // 8 scalars: a_i + c * r_i
    z2: vector<Element<Scalar>>, // 8 scalars: b_i + c * u_i
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

public fun new_key_consistency_proof(
    a1: vector<Element<G>>,
    a2: vector<Element<G>>,
    a3: Element<G>,
    z1: vector<Element<Scalar>>,
    z2: vector<Element<Scalar>>,
): KeyConsistencyProof {
    KeyConsistencyProof { a1, a2, a3, z1, z2 }
}

/// Verify a `DdhProof`: a single witness `w` maps every base to its image,
/// `images[k] == w * bases[k]` for all `k`.
public(package) fun verify_ddh(
    proof: &DdhProof,
    dst: vector<u8>,
    bases: &vector<Element<G>>,
    images: &vector<Element<G>>,
): bool {
    // TODO: check for degenerate case where a base is the identity element.
    let n = bases.length();
    if (images.length() != n || proof.commitments.length() != n) return false;
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
    pk: &Element<G>,
    encryptions: &vector<Encryption>,
): bool {
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    // TODO: can skip fixed g, h (left as a defense in depth)
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

/// Verify a `KeyConsistencyProof` against the recipient public keys and `encryptions[i]`, the
/// i-th-limb `MultiRecipientEncryption` (one shared `ciphertext` + one `decryption_handle` per
/// recipient).
public(package) fun verify_key_consistency(
    proof: &KeyConsistencyProof,
    dst: vector<u8>,
    sender_public_key: &Element<G>,
    recipient_encryption_keys: &vector<Element<G>>,
    encryptions: &vector<MultiRecipientEncryption>,
): bool {
    let n = KEY_CONSISTENCY_LIMBS;
    let m = recipient_encryption_keys.length();
    assert!(proof.a1.length() == n * m, EMalformedKeyConsistencyProof);
    assert!(proof.a2.length() == n, EMalformedKeyConsistencyProof);
    assert!(proof.z1.length() == n, EMalformedKeyConsistencyProof);
    assert!(proof.z2.length() == n, EMalformedKeyConsistencyProof);
    assert!(encryptions.length() == n, EMalformedKeyConsistencyProof);
    encryptions.do_ref!(
        |e| assert!(
            e.multi_recipient_decryption_handles().length() == m,
            EMalformedKeyConsistencyProof,
        ),
    );

    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    // TODO: can skip fixed g, h (left as a defense in depth)
    let c = challenge_key_consistency(
        dst,
        &g,
        &h,
        sender_public_key,
        recipient_encryption_keys,
        encryptions,
        &proof.a1,
        &proof.a2,
        &proof.a3,
    );

    // Check 1: A1_ij + c * D_ij == z1_i * pk_j for all (i, j)
    let mut i = 0;
    while (i < n) {
        let z1i = &proof.z1[i];
        let dhs = encryptions[i].multi_recipient_decryption_handles();
        let mut j = 0;
        while (j < m) {
            let a1ij = &proof.a1[i * m + j];
            if (!is_valid_relation(a1ij, &dhs[j], &recipient_encryption_keys[j], z1i, &c)) {
                return false
            };
            j = j + 1;
        };
        i = i + 1;
    };

    // Check 2: A2_i + c * C_i == z1_i * g + z2_i * h for all i
    let mut i = 0;
    while (i < n) {
        let a2i = &proof.a2[i];
        let ci = encryptions[i].multi_recipient_ciphertext();
        if (!is_valid_relation2(a2i, ci, &g, &h, &proof.z1[i], &proof.z2[i], &c)) return false;
        i = i + 1;
    };

    // Check 3: A3 + c * sender_public_key == (\sum_i z2_i * 2^{32i}) * g
    let base = scalar_from_u64(1u64 << 32);
    let mut exp = scalar_from_u64(1u64);
    let mut z_sum = scalar_from_u64(0u64);
    n.do!(|i| {
        let z2i = &proof.z2[i];
        z_sum = scalar_add(&z_sum, &scalar_mul(z2i, &exp));
        exp = scalar_mul(&exp, &base);
    });
    is_valid_relation(&proof.a3, sender_public_key, &g, &z_sum, &c)
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

/// Compute the Fiat-Shamir challenge for a `KeyConsistencyProof`. The transcript binds the bases
/// `g, h`, the sender public key, the recipient public keys, every per-limb ciphertext with its
/// decryption handles, and finally the prover commitments `(a1, a2, a3)`.
fun challenge_key_consistency(
    dst: vector<u8>,
    g: &Element<G>,
    h: &Element<G>,
    sender_public_key: &Element<G>,
    recipient_encryption_keys: &vector<Element<G>>,
    encryptions: &vector<MultiRecipientEncryption>,
    a1: &vector<Element<G>>,
    a2: &vector<Element<G>>,
    a3: &Element<G>,
): Element<Scalar> {
    let mut random_oracle_inputs = vector[dst, *g.bytes(), *h.bytes(), *sender_public_key.bytes()];
    recipient_encryption_keys.do_ref!(|rek| random_oracle_inputs.push_back(*rek.bytes()));
    // For each limb: first the commitment, then its decryption handles.
    encryptions.do_ref!(|e| {
        random_oracle_inputs.push_back(*e.multi_recipient_ciphertext().bytes());
        e
            .multi_recipient_decryption_handles()
            .do_ref!(|dh| random_oracle_inputs.push_back(*dh.bytes()));
    });
    a1.do_ref!(|a1i| random_oracle_inputs.push_back(*a1i.bytes()));
    a2.do_ref!(|a2i| random_oracle_inputs.push_back(*a2i.bytes()));
    random_oracle_inputs.push_back(*a3.bytes());
    fiat_shamir_challenge(random_oracle_inputs)
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

/// Build a DDH proof of knowledge of `r` such that `d_1 = r*pk_1` and `d_2 = r*pk_2` — i.e. the
/// same blinding `r` was used to produce both decryption handles, under (possibly) different
/// public keys.
#[test_only]
public fun handle_eq_proof_for_testing(
    dst: vector<u8>,
    pk_1: &Element<G>,
    pk_2: &Element<G>,
    d_1: &Element<G>,
    d_2: &Element<G>,
    r: &Element<Scalar>,
): DdhProof {
    prove_ddh(
        dst,
        r,
        &vector[*pk_1, *pk_2],
        &vector[*d_1, *d_2],
        &scalar_from_u64(123456), // randomness
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

/// Split a Ristretto scalar into eight little-endian 32-bit limbs. Used to construct the witness
/// for `prove_key_consistency` from a 256-bit private key.
#[test_only]
public fun scalar_to_limbs(sk: &Element<Scalar>): vector<u32> {
    let bytes = sk.bytes();
    vector::tabulate!(8, |i| {
        let offset = i * 4;
        (bytes[offset]       as u32)
        | ((bytes[offset + 1]   as u32) << 8)
        | ((bytes[offset + 2]   as u32) << 16)
        | ((bytes[offset + 3]   as u32) << 24)
    })
}

#[test_only]
public fun prove_key_consistency(
    dst: vector<u8>,
    sender_private_key_limbs: &vector<u32>,
    sender_public_key: &Element<G>,
    recipient_encryption_keys: &vector<Element<G>>,
    encryptions: &vector<MultiRecipientEncryption>,
    blindings: &vector<Element<Scalar>>,
    a: vector<Element<Scalar>>,
    b: vector<Element<Scalar>>,
): KeyConsistencyProof {
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    let n = sender_private_key_limbs.length();
    let m = recipient_encryption_keys.length();

    // a1[i*m + j] = a_i * pk_j for all limbs i and recipients j
    let mut a1 = vector[];
    n.do!(|i| {
        let ai = &a[i];
        m.do!(|j| {
            a1.push_back(g_mul(ai, &recipient_encryption_keys[j]));
        });
    });

    // a2[i] = a_i * g + b_i * h
    let mut a2 = vector[];
    n.do!(|i| {
        let ai = &a[i];
        let bi = &b[i];
        a2.push_back(g_add(&g_mul(ai, &g), &g_mul(bi, &h)));
    });

    // a3 = (\sum_i b_i * 2^{32i}) * g
    let base = scalar_from_u64(1u64 << 32);
    let mut exp = scalar_from_u64(1u64);
    let mut b_sum = scalar_from_u64(0u64);
    n.do!(|i| {
        b_sum = scalar_add(&b_sum, &scalar_mul(&b[i], &exp));
        exp = scalar_mul(&exp, &base);
    });
    let a3 = g_mul(&b_sum, &g);

    let c = challenge_key_consistency(
        dst,
        &g,
        &h,
        sender_public_key,
        recipient_encryption_keys,
        encryptions,
        &a1,
        &a2,
        &a3,
    );

    // z1[i] = a_i + c * r_i
    let mut z1 = vector[];
    n.do!(|i| {
        z1.push_back(scalar_add(&a[i], &scalar_mul(&c, &blindings[i])));
    });

    // z2[i] = b_i + c * u_i
    let mut z2 = vector[];
    n.do!(|i| {
        let ui = scalar_from_u64(sender_private_key_limbs[i] as u64);
        z2.push_back(scalar_add(&b[i], &scalar_mul(&c, &ui)));
    });

    KeyConsistencyProof { a1, a2, a3, z1, z2 }
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

#[test]
fun key_consistency_proof_round_trip() {
    let sk = scalar_from_u64(1234567890);
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();
    let sender_pk = g_mul(&sk, &g);

    let limbs = scalar_to_limbs(&sk);

    let recipient_pk_1 = g_mul(&scalar_from_u64(1111111111), &g);
    let recipient_pk_2 = g_mul(&scalar_from_u64(2222222222), &g);
    let recipient_pk_3 = g_mul(&scalar_from_u64(3333333333), &g);
    let recipient_encryption_keys = vector[recipient_pk_1, recipient_pk_2, recipient_pk_3];

    let mut encryptions = vector[];
    let mut blindings = vector[];
    let n = limbs.length();
    n.do!(|i| {
        let r = scalar_from_u64((i + 1) * 111);
        let u = scalar_from_u64(limbs[i] as u64);
        encryptions.push_back(
            twisted_elgamal::new_multi_recipient_encryption(
                g_add(&g_mul(&r, &g), &g_mul(&u, &h)),
                vector[
                    g_mul(&r, &recipient_pk_1),
                    g_mul(&r, &recipient_pk_2),
                    g_mul(&r, &recipient_pk_3),
                ],
            ),
        );
        blindings.push_back(r);
    });

    let mut a = vector[];
    let mut b = vector[];
    n.do!(|i| {
        a.push_back(scalar_from_u64((i + 1) * 777));
        b.push_back(scalar_from_u64((i + 1) * 888));
    });

    let proof = prove_key_consistency(
        vector[],
        &limbs,
        &sender_pk,
        &recipient_encryption_keys,
        &encryptions,
        &blindings,
        a,
        b,
    );

    assert!(
        verify_key_consistency(
            &proof,
            vector[],
            &sender_pk,
            &recipient_encryption_keys,
            &encryptions,
        ),
    );
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
    assert!(verify_elgamal(&proof, vector[], &pk, &encryptions));
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
    assert!(verify_elgamal(&proof, vector[], &pk, &encryptions));

    // Tampering with any ciphertext breaks verification.
    let mut bad = encryptions;
    *bad.borrow_mut(2) = twisted_elgamal::encrypt_trivial_for_testing(1, &pk, 333);
    assert!(!verify_elgamal(&proof, vector[], &pk, &bad));

    // A different key breaks verification.
    let other_pk = g_mul(&scalar_from_u64(99999), &twisted_elgamal::g());
    assert!(!verify_elgamal(&proof, vector[], &other_pk, &encryptions));
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
    assert!(!verify_elgamal(&proof, vector[], &pk, &prefix));

    // The proven batch extended by one more valid ciphertext.
    let mut extended = encryptions;
    extended.push_back(twisted_elgamal::encrypt_trivial_for_testing(9, &pk, 666));
    assert!(!verify_elgamal(&proof, vector[], &pk, &extended));

    // The proven ciphertexts in a different order.
    let mut swapped = encryptions;
    swapped.swap(0, 1);
    assert!(!verify_elgamal(&proof, vector[], &pk, &swapped));
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
