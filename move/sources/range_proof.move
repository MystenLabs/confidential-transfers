// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Batched Bulletproof range checks over Pedersen commitments.
///
/// A batch of any size is covered by one `RangeProofs`: the commitments are partitioned into
/// power-of-two chunks (`batch_sizes`), each proven by its own aggregated Bulletproof, because
/// Sui's verifier caps one proof at `MAX_BATCH_SIZE` commitments.
module contra::range_proof;

use sui::{group_ops::Element, rangeproofs, ristretto255::G};

// === Errors ===

const ERangeProofRequired: u64 = 0;
const EUnsupportedVersion: u64 = 1;

// === Constants ===

/// Bulletproof construction version.
const BULLETPROOFS_VERSION: u8 = 0;

/// Aggregated 16-bit Bulletproofs over Ristretto255.
const VERSION_BULLETPROOFS_16: u8 = 0;

/// Unproven range check — accepted by `verify` without verifying anything.
const VERSION_TESTING: u8 = 255;

/// Bit-length of the range check: every committed value must lie in `[0, 2^16)`.
const RANGE_BITS: u8 = 16;

/// Maximum number of commitments covered by a single Bulletproof.
/// `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255` caps the aggregated commitment
/// count at 32 for `RANGE_BITS = 16`.
const MAX_BATCH_SIZE: u64 = 32;

// === Structs ===

/// The range proofs for a range-check batch, tagged with the proof system that produced them.
/// `new_range_proofs` is the only production constructor and PTBs can't fabricate a struct, so a
/// batch verified on chain can never silently skip its range check. Move tests, which can't produce
/// Bulletproof bytes, use the `#[test_only]` `new_range_proof_for_testing` instead.
public struct RangeProofs has drop {
    version: u8,
    proofs: vector<vector<u8>>,
}

// === Functions ===

/// Wrap `proofs` into a `RangeProofs` to be checked as aggregated 16-bit Bulletproofs; rejects an
/// empty set, which would verify vacuously over an empty batch.
public fun new_range_proofs(proofs: vector<vector<u8>>): RangeProofs {
    assert!(!proofs.is_empty(), ERangeProofRequired);
    RangeProofs { version: VERSION_BULLETPROOFS_16, proofs }
}

/// Verify every `commitment` opens to a value in `[0, 2^RANGE_BITS)`, via one Bulletproof per chunk
/// of `batch_sizes`.
/// A `RangeProofs` from the `#[test_only]` `new_range_proof_for_testing` passes unconditionally.
public(package) fun verify(
    self: RangeProofs,
    commitments: &vector<Element<G>>,
    dst: vector<u8>,
): bool {
    let RangeProofs { version, proofs } = self;
    if (version == VERSION_TESTING) return true;
    // The only non-testing version — a new construction must add its own branch below.
    assert!(version == VERSION_BULLETPROOFS_16, EUnsupportedVersion);
    let sizes = batch_sizes(commitments.length());
    if (proofs.length() != sizes.length()) return false;
    let mut offset = 0;
    sizes.zip_map_ref!(&proofs, |chunk, range_proof| {
        let chunk = *chunk;
        let start = offset;
        offset = offset + chunk;
        rangeproofs::verify_bulletproofs_with_dst_ristretto255(
            range_proof,
            RANGE_BITS,
            &vector::tabulate!(chunk, |j| commitments[start + j]),
            &dst,
            BULLETPROOFS_VERSION,
        )
    }).all!(|ok| *ok)
}

/// Canonical Bulletproof chunking for `n` commitments: greedily take as many `MAX_BATCH_SIZE`
/// chunks as fit, then halve the chunk size and repeat until `n` is exhausted.
/// Examples (`MAX_BATCH_SIZE = 32`): n=7 → [4, 2, 1]; n=32 → [32]; n=36 → [32, 4]; n=0 → [].
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

// === Test Helpers ===

/// A `RangeProofs` that skips the range check — Move tests can't produce Bulletproof bytes, so they
/// assume the range instead of proving it.
///
/// WARNING: THE `#[test_only]` ATTRIBUTE BELOW IS LOAD-BEARING. IF THIS FUNCTION EVER BECAME
/// CALLABLE IN PRODUCTION, ANY PTB COULD PASS AN UNPROVEN `RangeProofs` AND SKIP RANGE VERIFICATION
/// ENTIRELY — OUT-OF-RANGE LIMBS (E.G. NEGATIVE-VALUE ENCODINGS) WOULD BE ACCEPTED, BREAKING THE
/// NO-OVERDRAFT/NO-INFLATION GUARANTEE OF THE WHOLE PROTOCOL. IT IS THE ONLY WAY TO CONSTRUCT A
/// `RangeProofs` THAT SKIPS VERIFICATION. NEVER REMOVE `#[test_only]` FROM IT.
#[test_only]
public fun new_range_proof_for_testing(): RangeProofs {
    RangeProofs { version: VERSION_TESTING, proofs: vector[] }
}
