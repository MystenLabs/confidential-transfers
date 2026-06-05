// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { BatchRangeProver } from './bp.js';
import { KeyConsistencyProof, scalarToLimbs } from './nizk.js';
import { randomScalar, type RistrettoPoint } from './ristretto255.js';
import { MultiRecipientEncryption, type PrivateKey } from './twisted_elgamal.js';

/** Bit-length of each private-key limb committed in the key encryption. */
const LIMB_BITS = 32;

/**
 * The bundle a user submits on `register` / `set_public_key` whenever the token has
 * auditors configured. Wraps:
 *   - per-limb `MultiRecipientEncryption` of the user's 32-bit private-key limbs
 *     under every auditor's public key,
 *   - a `KeyConsistencyProof` (sigma protocol) tying the encrypted limbs to the
 *     user's public key,
 *   - an aggregate Bulletproof showing each limb lies in `[0, 2^32)`.
 *
 * Mirrors `contra::auditors::KeyEncryption` on chain.
 */
export class KeyEncryption {
	ciphertexts: MultiRecipientEncryption[];
	proof: KeyConsistencyProof;
	rangeProof: Uint8Array;

	constructor(
		ciphertexts: MultiRecipientEncryption[],
		proof: KeyConsistencyProof,
		rangeProof: Uint8Array,
	) {
		this.ciphertexts = ciphertexts;
		this.proof = proof;
		this.rangeProof = rangeProof;
	}

	/**
	 * Build a `KeyEncryption` for the given private key under the auditor key set.
	 * Generates fresh blindings per limb, the sigma proof, and the aggregate
	 * Bulletproof in one call. `batchRangeProver` is a bound function from the
	 * caller's `getBulletproofs()` result (WASM already initialized).
	 */
	static prove(
		batchRangeProver: BatchRangeProver,
		dst: Uint8Array,
		senderPrivateKey: PrivateKey,
		senderPublicKey: RistrettoPoint,
		auditorPublicKeys: RistrettoPoint[],
	): KeyEncryption {
		const limbs = scalarToLimbs(senderPrivateKey);
		const blindings: bigint[] = [];
		const ciphertexts = limbs.map((limb) => {
			const r = randomScalar();
			blindings.push(r);
			return MultiRecipientEncryption.encrypt(auditorPublicKeys, limb, r);
		});
		const proof = KeyConsistencyProof.prove(
			dst,
			limbs,
			senderPublicKey,
			auditorPublicKeys,
			ciphertexts,
			blindings,
		);
		const { proof: rangeProof } = batchRangeProver(limbs, blindings, LIMB_BITS);
		return new KeyEncryption(ciphertexts, proof, rangeProof);
	}
}
