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

// === Constants ===

/// Bulletproof construction version.
const BULLETPROOFS_VERSION: u8 = 0;

/// Bit-length of the range check: every committed value must lie in `[0, 2^16)`.
const RANGE_BITS: u8 = 16;

/// Maximum number of commitments covered by a single Bulletproof.
/// `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255` caps the aggregated commitment
/// count at 32 for `RANGE_BITS = 16`.
const MAX_BATCH_SIZE: u64 = 32;

// === Structs ===

/// The Bulletproof range proofs for a range-check batch (one per `batch_sizes` chunk). The only
/// production constructor (`new_range_proofs`) rejects an empty set, and PTBs can't fabricate a
/// struct, so a batch verified on chain can never silently skip its range check. Move tests, which
/// can't produce Bulletproof bytes, use the `#[test_only]` `assume_range_checked` instead.
public struct RangeProofs has drop {
    proofs: vector<vector<u8>>,
}

// === Functions ===

/// Wrap `proofs` into `RangeProofs`; rejects an empty set so the range check can't be skipped on chain.
public fun new_range_proofs(proofs: vector<vector<u8>>): RangeProofs {
    assert!(!proofs.is_empty() && proofs.all!(|p| !p.is_empty()), ERangeProofRequired);
    RangeProofs { proofs }
}

/// Verify every `commitment` opens to a value in `[0, 2^RANGE_BITS)`, via one Bulletproof per chunk
/// of `batch_sizes`.
/// An empty `self` skips the check — only reachable via the `#[test_only]`
/// `assume_range_checked`.
public(package) fun verify(
    self: RangeProofs,
    commitments: &vector<Element<G>>,
    dst: vector<u8>,
): bool {
    let RangeProofs { proofs } = self;
    if (proofs.is_empty()) return true;
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

/// `RangeProofs` that skips the range check — Move tests can't produce Bulletproof bytes, so they
/// assume the range instead of proving it.
///
/// WARNING: THE `#[test_only]` ATTRIBUTE BELOW IS LOAD-BEARING. IF THIS FUNCTION EVER BECAME
/// CALLABLE IN PRODUCTION, ANY PTB COULD PASS AN EMPTY `RangeProofs` AND SKIP RANGE VERIFICATION
/// ENTIRELY — OUT-OF-RANGE LIMBS (E.G. NEGATIVE-VALUE ENCODINGS) WOULD BE ACCEPTED, BREAKING THE
/// NO-OVERDRAFT/NO-INFLATION GUARANTEE OF THE WHOLE PROTOCOL. IT IS THE ONLY WAY TO CONSTRUCT AN
/// EMPTY `RangeProofs` (`new_range_proofs` REJECTS ONE). NEVER REMOVE `#[test_only]` FROM IT.
#[test_only]
public fun assume_range_checked(): RangeProofs {
    RangeProofs { proofs: vector[] }
}
