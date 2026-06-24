// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Simple deserialization functions that build the composite crypto types from their
/// byte-encoded elements in a single Move call.
module contra::decode;

use contra::{
    encrypted_amount::{
        new_consistency_proof,
        new_encrypted_amount,
        ConsistencyProof,
        EncryptedAmount
    },
    nizk::{Self, DdhProof, BatchedDdhProof, ElGamalProof, KeyConsistencyProof},
    twisted_elgamal::{Self, Encryption, MultiRecipientEncryption}
};
use sui::{group_ops::Element, ristretto255::{G, Scalar, g_from_bytes, scalar_from_bytes}};

const KEY_LIMBS: u64 = 8;

public fun g_vector(parts: vector<vector<u8>>): vector<Element<G>> {
    parts.map!(|b| g_from_bytes(&b))
}

public fun encryption(parts: vector<vector<u8>>): Encryption {
    encryption_at(&parts, 0)
}

public fun encrypted_amount(parts: vector<vector<u8>>): EncryptedAmount {
    new_encrypted_amount(
        encryption_at(&parts, 0),
        encryption_at(&parts, 2),
        encryption_at(&parts, 4),
        encryption_at(&parts, 6),
    )
}

public fun multi_recipient_encryption(parts: vector<vector<u8>>, m: u64): MultiRecipientEncryption {
    twisted_elgamal::new_multi_recipient_encryption(
        g_from_bytes(parts.borrow(0)),
        g_range(&parts, 1, m),
    )
}

public fun ddh_proof(parts: vector<vector<u8>>): DdhProof {
    nizk::new_ddh_proof(
        g_from_bytes(parts.borrow(0)),
        g_from_bytes(parts.borrow(1)),
        scalar_from_bytes(parts.borrow(2)),
    )
}

/// Decode a `BatchedDdhProof` from `[commitment_0, ..., commitment_{n-1}, z]`: the trailing part is
/// the scalar response `z`, the rest are the per-pair Schnorr commitments.
public fun batched_ddh_proof(parts: vector<vector<u8>>): BatchedDdhProof {
    let n = parts.length() - 1;
    nizk::new_batched_ddh_proof(g_range(&parts, 0, n), scalar_from_bytes(parts.borrow(n)))
}

public fun elgamal_proof(parts: vector<vector<u8>>): ElGamalProof {
    elgamal_proof_at(&parts, 0)
}

public fun consistency_proof(parts: vector<vector<u8>>): ConsistencyProof {
    new_consistency_proof(
        elgamal_proof_at(&parts, 0),
        elgamal_proof_at(&parts, 4),
        elgamal_proof_at(&parts, 8),
        elgamal_proof_at(&parts, 12),
    )
}

public fun key_consistency_proof(parts: vector<vector<u8>>, m: u64): KeyConsistencyProof {
    let a1_count = KEY_LIMBS * m;
    let a2_start = a1_count;
    let a3_idx = a2_start + KEY_LIMBS;
    let z1_start = a3_idx + 1;
    let z2_start = z1_start + KEY_LIMBS;
    nizk::new_key_consistency_proof(
        g_range(&parts, 0, a1_count),
        g_range(&parts, a2_start, KEY_LIMBS),
        g_from_bytes(parts.borrow(a3_idx)),
        scalar_range(&parts, z1_start, KEY_LIMBS),
        scalar_range(&parts, z2_start, KEY_LIMBS),
    )
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

fun scalar_range(parts: &vector<vector<u8>>, start: u64, count: u64): vector<Element<Scalar>> {
    let mut out = vector[];
    let mut i = 0;
    while (i < count) {
        out.push_back(scalar_from_bytes(parts.borrow(start + i)));
        i = i + 1;
    };
    out
}
