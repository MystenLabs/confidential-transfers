// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Simple deserialization functions that build the composite crypto types from their
/// byte-encoded elements in a single Move call.
module contra::decode;

use contra::{
    encrypted_amount::{new_encrypted_amount, EncryptedAmount},
    nizk::{Self, DdhProof, ElGamalProof},
    twisted_elgamal::{Self, Encryption, PublicKey, public_key}
};
use sui::{group_ops::Element, ristretto255::{G, g_from_bytes, scalar_from_bytes}};

entry fun g_vector(parts: vector<vector<u8>>): vector<Element<G>> {
    parts.map!(|b| g_from_bytes(&b))
}

/// Build one `PublicKey` per point-encoded part; each is validated non-identity by `public_key`.
entry fun public_keys(parts: vector<vector<u8>>): vector<PublicKey> {
    parts.map!(|b| public_key(g_from_bytes(&b)))
}

/// Build one `[lo, hi]` handle pair per consecutive pair of point-encoded `parts` (two u32-limb
/// handles per transferred amount, flattened in amount order). Aborts if `parts` has an odd length.
entry fun auditor_decryption_handles(parts: vector<vector<u8>>): vector<vector<Element<G>>> {
    let elements = g_vector(parts);
    let mut out = vector[];
    let mut i = 0;
    while (i < elements.length()) {
        out.push_back(vector[elements[i], elements[i + 1]]);
        i = i + 2;
    };
    out
}

entry fun encryption(parts: vector<vector<u8>>): Encryption {
    encryption_at(&parts, 0)
}

entry fun encrypted_amount(parts: vector<vector<u8>>): EncryptedAmount {
    new_encrypted_amount(
        encryption_at(&parts, 0),
        encryption_at(&parts, 2),
        encryption_at(&parts, 4),
        encryption_at(&parts, 6),
    )
}

/// Build one `EncryptedAmount` per 8 consecutive point-encoded `parts` (four limbs, each a
/// ciphertext + handle), in amount order. Aborts if `parts.length()` is not a multiple of 8.
entry fun encrypted_amounts(parts: vector<vector<u8>>): vector<EncryptedAmount> {
    let mut out = vector[];
    let mut i = 0;
    while (i < parts.length()) {
        out.push_back(
            new_encrypted_amount(
                encryption_at(&parts, i),
                encryption_at(&parts, i + 2),
                encryption_at(&parts, i + 4),
                encryption_at(&parts, i + 6),
            ),
        );
        i = i + 8;
    };
    out
}

entry fun ddh_proof(parts: vector<vector<u8>>): DdhProof {
    let n = parts.length() - 1;
    nizk::new_ddh_proof(g_range(&parts, 0, n), scalar_from_bytes(parts.borrow(n)))
}

entry fun elgamal_proof(parts: vector<vector<u8>>): ElGamalProof {
    elgamal_proof_at(&parts, 0)
}

/// Build one folded `ElGamalProof` per 4 consecutive parts (`a`, `b`, `z1`, `z2`), in order.
/// Aborts if `parts.length()` is not a multiple of 4.
entry fun elgamal_proofs(parts: vector<vector<u8>>): vector<ElGamalProof> {
    let mut out = vector[];
    let mut i = 0;
    while (i < parts.length()) {
        out.push_back(elgamal_proof_at(&parts, i));
        i = i + 4;
    };
    out
}

fun encryption_at(parts: &vector<vector<u8>>, off: u64): Encryption {
    twisted_elgamal::new(g_from_bytes(parts.borrow(off)), g_from_bytes(parts.borrow(off + 1)))
}

fun elgamal_proof_at(parts: &vector<vector<u8>>, off: u64): ElGamalProof {
    nizk::new_elgamal_proof(
        g_from_bytes(parts.borrow(off)),
        g_from_bytes(parts.borrow(off + 1)),
        scalar_from_bytes(parts.borrow(off + 2)),
        scalar_from_bytes(parts.borrow(off + 3)),
    )
}

fun g_range(parts: &vector<vector<u8>>, start: u64, count: u64): vector<Element<G>> {
    let mut out = vector[];
    let mut i = 0;
    while (i < count) {
        out.push_back(g_from_bytes(parts.borrow(start + i)));
        i = i + 1;
    };
    out
}
