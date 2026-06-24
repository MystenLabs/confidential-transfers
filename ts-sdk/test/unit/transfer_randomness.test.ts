// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import {
	recoverTransferRandomness,
	sampleTransferRandomness,
} from '../../src/transfer_randomness.js';
import {
	Ciphertext,
	DiscreteLogTable,
	EncryptedAmount,
	generateKeyPair,
} from '../../src/twisted_elgamal.js';

/** Split a u64 into its four u16 limbs, matching the on-chain `from_value`. */
function limbsOf(value: bigint): bigint[] {
	return [
		value & 0xffffn,
		(value >> 16n) & 0xffffn,
		(value >> 32n) & 0xffffn,
		(value >> 48n) & 0xffffn,
	];
}

describe('transfer randomness', () => {
	const table = DiscreteLogTable.create(16);

	it('sender and recovery derive the same seed (t·pk == sk·P)', () => {
		const [pk, sk] = generateKeyPair();
		const r = sampleTransferRandomness(pk);
		const recovered = recoverTransferRandomness(sk, r.seedPoint);
		expect(recovered.blinding(0, 0)).toEqual(r.blinding(0, 0));
		expect(recovered.blinding(6, 3)).toEqual(r.blinding(6, 3));
	});

	it('blindings are distinct across (recipient, limb)', () => {
		const [pk] = generateKeyPair();
		const r = sampleTransferRandomness(pk);
		const seen = new Set<bigint>();
		for (let i = 0; i < 4; i++) {
			for (let j = 0; j < 4; j++) {
				seen.add(r.blinding(i, j));
			}
		}
		expect(seen.size).toEqual(16);
	});

	it('sender recovers its own batched-transfer amounts from P and sk', () => {
		const [senderPk, senderSk] = generateKeyPair();
		const [receiverPk] = generateKeyPair();
		const randomness = sampleTransferRandomness(senderPk);

		// recipients 0..2; the middle amount crosses the first limb boundary.
		const amounts = [42n, 100_000n, 65_535n];

		// Encrypt each amount under the receiver key using the seed-derived blindings, exactly as
		// the client does, then keep only the resulting commitments in an `EncryptedAmount`.
		const encrypted = amounts.map((amount, i) => {
			const limbs = limbsOf(amount).map(
				(v, j) =>
					Ciphertext.encryptWithBlinding(receiverPk, v, randomness.blinding(i, j)).ciphertext,
			);
			return new EncryptedAmount(limbs[0], limbs[1], limbs[2], limbs[3]);
		});

		// Recover from sk + P alone — no decryption handles.
		const recovered = recoverTransferRandomness(senderSk, randomness.seedPoint);
		amounts.forEach((amount, i) => {
			const value = encrypted[i].decryptWithBlindings((j) => recovered.blinding(i, j), table);
			expect(value).toEqual(amount);
		});
	});

	it('a wrong secret key cannot recover the amount', () => {
		const [senderPk] = generateKeyPair();
		const [, wrongSk] = generateKeyPair();
		const randomness = sampleTransferRandomness(senderPk);
		const { ciphertext } = Ciphertext.encryptWithBlinding(senderPk, 7n, randomness.blinding(0, 0));
		const amount = new EncryptedAmount(
			ciphertext,
			Ciphertext.trivial(0n),
			Ciphertext.trivial(0n),
			Ciphertext.trivial(0n),
		);
		const recovered = recoverTransferRandomness(wrongSk, randomness.seedPoint);
		// Wrong seed → wrong blinding → the residual is not a small multiple of H, so the dlog search
		// exhausts the table and throws. Use a tiny table so the (necessarily full) scan is cheap.
		const smallTable = DiscreteLogTable.create(8);
		expect(() =>
			amount.decryptWithBlindings((j) => recovered.blinding(0, j), smallTable),
		).toThrow();
	});
});
