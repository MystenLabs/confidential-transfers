// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ristretto255 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE } from '@noble/curves/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { G, mul, randomScalar, type RistrettoPoint } from './ristretto255.js';
import type { PrivateKey, PublicKey } from './twisted_elgamal.js';

/**
 * Per-transfer randomness for a batched transfer.
 *
 * The sender draws one scalar `t`, publishes `P = t * G`, and derives every
 * per-(recipient, limb) blinding from `seed = HKDF(t * senderPk) = HKDF(sk * P)`.
 * This lets the sender recover its outgoing amounts later from `sk` and the on-chain
 * `P` alone, with no per-transfer secret state (see `TokenAccount.recoverSentAmount`).
 */
export interface TransferRandomness {
	readonly seedPoint: RistrettoPoint;
	/** The blinding `r_{i,j}` for `batchIndex` `i`, limb `j`. */
	blinding(batchIndex: number, limbIndex: number): bigint;
}

/** HKDF `info` domain-separating the seed derivation. */
const SEED_INFO = new TextEncoder().encode('contra/transfer-seed/v1');

/**
 * Sample fresh per-transfer randomness for a transfer signed under `senderPk`.
 */
export function sampleTransferRandomness(senderPk: PublicKey): TransferRandomness {
	const t = randomScalar();
	return fromSharedSecret(mul(G, t), mul(senderPk, t));
}

/**
 * Reconstruct the blindings of a past transfer from the sender's secret key and
 * the published point `P`.
 */
export function recoverTransferRandomness(
	sk: PrivateKey,
	seedPoint: RistrettoPoint,
): TransferRandomness {
	return fromSharedSecret(seedPoint, mul(seedPoint, sk));
}

function fromSharedSecret(seedPoint: RistrettoPoint, shared: RistrettoPoint): TransferRandomness {
	const seed = hkdf(sha256, shared.toBytes(), undefined, SEED_INFO, 32);
	return {
		seedPoint,
		blinding(batchIndex: number, limbIndex: number): bigint {
			const wide = hkdf(sha256, seed, undefined, Uint8Array.from([batchIndex, limbIndex]), 64);
			return ristretto255.Point.Fn.create(bytesToNumberLE(wide));
		},
	};
}
