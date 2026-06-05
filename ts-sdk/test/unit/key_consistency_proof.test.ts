// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import { KeyConsistencyProof, limbsToScalar, scalarToLimbs } from '../../src/nizk.js';
import { G, randomScalar } from '../../src/ristretto255.js';
import { MultiRecipientEncryption } from '../../src/twisted_elgamal.js';

const dst = new Uint8Array(38);

/** Build the per-limb ciphertexts and blindings for a given private key and recipient list. */
function buildCiphertexts(
	limbs: bigint[],
	recipientKeys: ReturnType<typeof G.multiply>[],
	blindingFn: (i: number) => bigint = (i) => BigInt((i + 1) * 111),
): { ciphertexts: MultiRecipientEncryption[]; blindings: bigint[] } {
	const ciphertexts: MultiRecipientEncryption[] = [];
	const blindings: bigint[] = [];
	for (let i = 0; i < limbs.length; i++) {
		const r = blindingFn(i);
		ciphertexts.push(MultiRecipientEncryption.encrypt(recipientKeys, limbs[i], r));
		blindings.push(r);
	}
	return { ciphertexts, blindings };
}

describe('KeyConsistencyProof', () => {
	const senderPrivateKey = 1234567890n;
	const senderPublicKey = G.multiply(senderPrivateKey);
	const limbs = scalarToLimbs(senderPrivateKey);

	const recipientKeys = [1111111111n, 2222222222n, 3333333333n].map((sk) => G.multiply(sk));

	it('prove and verify round-trips with a single recipient', () => {
		const singleRecipient = [recipientKeys[0]];
		const { ciphertexts, blindings } = buildCiphertexts(limbs, singleRecipient);
		const proof = KeyConsistencyProof.prove(
			dst,
			limbs,
			senderPublicKey,
			singleRecipient,
			ciphertexts,
			blindings,
		);
		expect(proof.verify(dst, senderPublicKey, singleRecipient, ciphertexts)).toBe(true);
	});

	it('prove and verify round-trips with multiple recipients', () => {
		const { ciphertexts, blindings } = buildCiphertexts(limbs, recipientKeys);
		const proof = KeyConsistencyProof.prove(
			dst,
			limbs,
			senderPublicKey,
			recipientKeys,
			ciphertexts,
			blindings,
		);
		expect(proof.verify(dst, senderPublicKey, recipientKeys, ciphertexts)).toBe(true);
	});

	it('verify fails with a wrong sender public key', () => {
		const { ciphertexts, blindings } = buildCiphertexts(limbs, recipientKeys);
		const proof = KeyConsistencyProof.prove(
			dst,
			limbs,
			senderPublicKey,
			recipientKeys,
			ciphertexts,
			blindings,
		);
		const wrongSenderPublicKey = G.multiply(9999999999n);
		expect(proof.verify(dst, wrongSenderPublicKey, recipientKeys, ciphertexts)).toBe(false);
	});

	it('verify fails with a wrong recipient key', () => {
		const { ciphertexts, blindings } = buildCiphertexts(limbs, recipientKeys);
		const proof = KeyConsistencyProof.prove(
			dst,
			limbs,
			senderPublicKey,
			recipientKeys,
			ciphertexts,
			blindings,
		);
		const wrongRecipientKeys = [G.multiply(4444444444n), ...recipientKeys.slice(1)];
		expect(proof.verify(dst, senderPublicKey, wrongRecipientKeys, ciphertexts)).toBe(false);
	});

	it('limbsToScalar inverts scalarToLimbs for random scalars', () => {
		for (let i = 0; i < 16; i++) {
			const sk = randomScalar();
			expect(limbsToScalar(scalarToLimbs(sk))).toBe(sk);
		}
	});

	it('prove and verify round-trips with a random private key', () => {
		const sk = randomScalar();
		const pk = G.multiply(sk);
		const skLimbs = scalarToLimbs(sk);
		const { ciphertexts, blindings } = buildCiphertexts(skLimbs, recipientKeys, () =>
			randomScalar(),
		);
		const proof = KeyConsistencyProof.prove(
			dst,
			skLimbs,
			pk,
			recipientKeys,
			ciphertexts,
			blindings,
		);
		expect(proof.verify(dst, pk, recipientKeys, ciphertexts)).toBe(true);
	});
});
