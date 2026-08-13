// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WASM bindings for `fastcrypto::bulletproofs` — a thin wrapper exposing
//! `RangeProof::prove` / `RangeProof::verify` to JavaScript.
//!
//! Proofs produced here are byte-compatible with `fastcrypto::bulletproofs`
//! and use fastcrypto's `PedersenCommitment` generators (`H`, `G`), which
//! differ from `bulletproofs::PedersenGens::default()`.

use fastcrypto::bulletproofs::{Range, RangeProof};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use fastcrypto::serde_helpers::ToFromByteArray;
use wasm_bindgen::prelude::*;

/// Output of a batched range proof: the single aggregate proof plus the
/// `32 * values.len()` bytes of concatenated Pedersen commitments, one per
/// input value, in order.
#[wasm_bindgen]
pub struct BatchRangeProofResult {
    proof_bytes: Vec<u8>,
    commitments_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl BatchRangeProofResult {
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Vec<u8> {
        self.proof_bytes.clone()
    }

    /// Concatenated 32-byte commitments, in the same order as the input values.
    #[wasm_bindgen(getter)]
    pub fn commitments(&self) -> Vec<u8> {
        self.commitments_bytes.clone()
    }
}

/// Aggregate range proof that `values[i] ∈ [0, 2^bit_size)` for every `i`,
/// using fastcrypto's `RangeProof::prove_batch`.
///
/// `values.len()` must be a power of 2 and equal to `blindings.len() / 32`;
/// `blindings` is `32 * values.len()` bytes, each a canonical ristretto255
/// scalar. `dst` is the domain-separation tag bound into the proof transcript;
/// the verifier must supply the same tag.
#[wasm_bindgen(js_name = batchRangeProof)]
pub fn batch_range_proof(
    values: &[u64],
    blindings: &[u8],
    bit_size: u32,
    dst: &[u8],
) -> Result<BatchRangeProofResult, JsError> {
    let range = range_from_bits(bit_size)?;
    let n = values.len();
    if blindings.len() != 32 * n {
        return Err(JsError::new("blindings must be 32 * values.len() bytes"));
    }
    let blindings: Vec<Blinding> = blindings
        .chunks(32)
        .map(blinding_from_bytes)
        .collect::<Result<_, _>>()?;

    let proof = RangeProof::prove_batch(values, &blindings, &range, dst, &mut rand::thread_rng())
        .map_err(|e| JsError::new(&format!("prove_batch failed: {:?}", e)))?;

    let commitments_bytes: Vec<u8> = values
        .iter()
        .map(|&v| RistrettoScalar::from(v))
        .zip(&blindings)
        .flat_map(|(v, b)| PedersenCommitment::new(&v, b).0.to_byte_array())
        .collect();

    Ok(BatchRangeProofResult {
        proof_bytes: proof.to_bytes(),
        commitments_bytes,
    })
}

/// Verify an aggregate range proof that every commitment encodes a value in
/// `[0, 2^bit_size)`, using `fastcrypto::bulletproofs::RangeProof::verify_batch`.
///
/// `commitments` is a flat buffer of 32-byte ristretto255 points concatenated
/// in the same order the proof was generated with. The number of commitments
/// must be a power of 2 and equal to the one used when proving. `dst` must match
/// the tag used when proving.
#[wasm_bindgen(js_name = verifyBatchRangeProof)]
pub fn verify_batch_range_proof(
    proof: &[u8],
    commitments: &[u8],
    bit_size: u32,
    dst: &[u8],
) -> Result<bool, JsError> {
    let range = range_from_bits(bit_size)?;
    if commitments.len() % 32 != 0 {
        return Err(JsError::new("commitments must be a multiple of 32 bytes"));
    }
    let commitments: Vec<PedersenCommitment> = commitments
        .chunks(32)
        .map(commitment_from_bytes)
        .collect::<Result<_, _>>()?;
    let proof = RangeProof::from_bytes(proof)
        .map_err(|e| JsError::new(&format!("invalid proof bytes: {:?}", e)))?;
    Ok(proof.verify_batch(&commitments, &range, dst, &mut rand::thread_rng()).is_ok())
}

fn range_from_bits(bit_size: u32) -> Result<Range, JsError> {
    match bit_size {
        8 => Ok(Range::Bits8),
        16 => Ok(Range::Bits16),
        32 => Ok(Range::Bits32),
        64 => Ok(Range::Bits64),
        _ => Err(JsError::new("bit_size must be 8, 16, 32, or 64")),
    }
}

fn blinding_from_bytes(bytes: &[u8]) -> Result<Blinding, JsError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new("blinding must be 32 bytes"))?;
    let scalar = RistrettoScalar::from_byte_array(&array)
        .map_err(|_| JsError::new("blinding is not a canonical scalar"))?;
    Ok(Blinding(scalar))
}

fn commitment_from_bytes(bytes: &[u8]) -> Result<PedersenCommitment, JsError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new("commitment must be 32 bytes"))?;
    let point = RistrettoPoint::from_byte_array(&array)
        .map_err(|_| JsError::new("commitment is not a valid ristretto point"))?;
    Ok(PedersenCommitment(point))
}
