// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Optional convenience deserializers that build the composite crypto types from their byte-encoded
/// elements in a single Move call. Do not check the input validity.
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

entry fun public_keys(parts: vector<vector<u8>>): vector<PublicKey> {
    parts.map!(|b| public_key(g_from_bytes(&b)))
}

/// Build one `[lo, hi]` handle pair per consecutive pair of point-encoded `parts`.
entry fun auditor_decryption_handles(parts: vector<vector<u8>>): vector<vector<Element<G>>> {
    vector::tabulate!(
        parts.length() / 2,
        |i| vector[g_from_bytes(parts.borrow(2 * i)), g_from_bytes(parts.borrow(2 * i + 1))],
    )
}

entry fun encryption(parts: vector<vector<u8>>): Encryption {
    encryption_at(&parts, 0)
}

entry fun encrypted_amount(parts: vector<vector<u8>>): EncryptedAmount {
    encrypted_amount_at(&parts, 0)
}

entry fun encrypted_amounts(parts: vector<vector<u8>>): vector<EncryptedAmount> {
    vector::tabulate!(parts.length() / 8, |i| encrypted_amount_at(&parts, i * 8))
}

entry fun ddh_proof(parts: vector<vector<u8>>): DdhProof {
    let n = parts.length() - 1;
    let commitments = vector::tabulate!(n, |i| g_from_bytes(parts.borrow(i)));
    nizk::new_ddh_proof(commitments, scalar_from_bytes(parts.borrow(n)))
}

entry fun elgamal_proof(parts: vector<vector<u8>>): ElGamalProof {
    elgamal_proof_at(&parts, 0)
}

entry fun elgamal_proofs(parts: vector<vector<u8>>): vector<ElGamalProof> {
    vector::tabulate!(parts.length() / 4, |i| elgamal_proof_at(&parts, i * 4))
}

fun encryption_at(parts: &vector<vector<u8>>, off: u64): Encryption {
    twisted_elgamal::new(g_from_bytes(parts.borrow(off)), g_from_bytes(parts.borrow(off + 1)))
}

fun encrypted_amount_at(parts: &vector<vector<u8>>, off: u64): EncryptedAmount {
    new_encrypted_amount(
        encryption_at(parts, off),
        encryption_at(parts, off + 2),
        encryption_at(parts, off + 4),
        encryption_at(parts, off + 6),
    )
}

fun elgamal_proof_at(parts: &vector<vector<u8>>, off: u64): ElGamalProof {
    nizk::new_elgamal_proof(
        g_from_bytes(parts.borrow(off)),
        g_from_bytes(parts.borrow(off + 1)),
        scalar_from_bytes(parts.borrow(off + 2)),
        scalar_from_bytes(parts.borrow(off + 3)),
    )
}
