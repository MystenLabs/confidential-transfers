// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ristretto255 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';

import { DecryptionFailedError } from '../../src/error.js';
import { H, randomScalar } from '../../src/ristretto255.js';
import {
	Ciphertext,
	computeTableEntries,
	DiscreteLogTable,
	EncryptedAmount,
	generateKeyPair,
	MultiRecipientEncryption,
} from '../../src/twisted_elgamal.js';

describe('twisted elgamal', () => {
	const table = DiscreteLogTable.create(16);

	it('encryption roundtrip', () => {
		const [pk, sk] = generateKeyPair();
		const m = 13322n;
		const { ciphertext } = Ciphertext.encrypt(pk, m);
		const decrypted = ciphertext.decrypt(sk, table);
		expect(decrypted).toEqual(m);
	});

	it('decrypts small values', () => {
		const [pk, sk] = generateKeyPair();
		for (const m of [1n, 42n, 255n, 1000n, 65535n]) {
			const { ciphertext } = Ciphertext.encrypt(pk, m);
			expect(ciphertext.decrypt(sk, table)).toEqual(m);
		}
	});

	it('decrypts value at giant step boundary', () => {
		const [pk, sk] = generateKeyPair();
		const m = 65536n;
		const { ciphertext } = Ciphertext.encrypt(pk, m);
		expect(ciphertext.decrypt(sk, table)).toEqual(m);
	});

	it('decrypts value crossing giant step boundary', () => {
		const [pk, sk] = generateKeyPair();
		const m = 70000n;
		const { ciphertext } = Ciphertext.encrypt(pk, m);
		expect(ciphertext.decrypt(sk, table)).toEqual(m);
	});

	it('decrypt uses cache on second call', () => {
		const [pk, sk] = generateKeyPair();
		const { ciphertext } = Ciphertext.encrypt(pk, 42n);
		const first = ciphertext.decrypt(sk, table);
		const second = ciphertext.decrypt(sk, table);
		expect(first).toEqual(42n);
		expect(second).toEqual(42n);
	});

	it('different keys produce different ciphertexts', () => {
		const [pk1, sk1] = generateKeyPair();
		const [pk2, sk2] = generateKeyPair();
		const c1 = Ciphertext.encrypt(pk1, 100n);
		const c2 = Ciphertext.encrypt(pk2, 100n);
		expect(c1.ciphertext.ciphertext.equals(c2.ciphertext.ciphertext)).toBe(false);
		expect(c1.ciphertext.decrypt(sk1, table)).toEqual(100n);
		expect(c2.ciphertext.decrypt(sk2, table)).toEqual(100n);
	});

	it('wrong key throws DecryptionFailedError', { timeout: 30_000 }, () => {
		const [pk1] = generateKeyPair();
		const [, sk2] = generateKeyPair();
		const { ciphertext } = Ciphertext.encrypt(pk1, 42n);
		expect(() => ciphertext.decrypt(sk2, table)).toThrow(DecryptionFailedError);
	});

	it('out-of-range plaintext throws DecryptionFailedError', { timeout: 30_000 }, () => {
		const smallTable = DiscreteLogTable.create(8);
		const [pk, sk] = generateKeyPair();
		// 2^16 is just past the 8-bit table's 2^16 search range.
		const { ciphertext } = Ciphertext.encrypt(pk, 1n << 16n);
		expect(() => ciphertext.decrypt(sk, smallTable)).toThrow(DecryptionFailedError);
	});

	describe('proveDecryption / verifyDecryption', () => {
		const DST = Uint8Array.from(Array.from({ length: 21 }, (_, i) => (i * 17 + 1) & 0xff));

		it('Ciphertext: honest proof verifies', () => {
			const [pk, sk] = generateKeyPair();
			const m = 12345n;
			const { ciphertext } = Ciphertext.encrypt(pk, m);
			const proof = ciphertext.proveDecryption(DST, sk, pk, m);
			expect(ciphertext.verifyDecryption(DST, pk, m, proof)).toBe(true);
		});

		it('Ciphertext: zero plaintext verifies', () => {
			const [pk, sk] = generateKeyPair();
			const { ciphertext } = Ciphertext.encrypt(pk, 0n);
			const proof = ciphertext.proveDecryption(DST, sk, pk, 0n);
			expect(ciphertext.verifyDecryption(DST, pk, 0n, proof)).toBe(true);
		});

		it('Ciphertext: proof rejects a wrong claimed value', () => {
			const [pk, sk] = generateKeyPair();
			const { ciphertext } = Ciphertext.encrypt(pk, 100n);
			const proof = ciphertext.proveDecryption(DST, sk, pk, 100n);
			expect(ciphertext.verifyDecryption(DST, pk, 101n, proof)).toBe(false);
		});

		it('Ciphertext: proof for wrong value does not verify under the true value', () => {
			const [pk, sk] = generateKeyPair();
			const { ciphertext } = Ciphertext.encrypt(pk, 100n);
			// Prover lies and proves 99 — the proof itself is a valid
			// DDH tuple proof but not for the residue at value=100, so
			// verification under the true value fails.
			const lyingProof = ciphertext.proveDecryption(DST, sk, pk, 99n);
			expect(ciphertext.verifyDecryption(DST, pk, 100n, lyingProof)).toBe(false);
			// And the lie does not verify either (the residue is not r*G).
			expect(ciphertext.verifyDecryption(DST, pk, 99n, lyingProof)).toBe(false);
		});

		it('Ciphertext: proof from one account does not verify under another pk', () => {
			const [pk1, sk1] = generateKeyPair();
			const [pk2] = generateKeyPair();
			const { ciphertext } = Ciphertext.encrypt(pk1, 42n);
			const proof = ciphertext.proveDecryption(DST, sk1, pk1, 42n);
			expect(ciphertext.verifyDecryption(DST, pk2, 42n, proof)).toBe(false);
		});

		it('EncryptedAmount: prove on collapsed ciphertext verifies', () => {
			const [pk, sk] = generateKeyPair();
			const amount = new EncryptedAmount(
				Ciphertext.encrypt(pk, 100n).ciphertext,
				Ciphertext.encrypt(pk, 200n).ciphertext,
				Ciphertext.encrypt(pk, 3n).ciphertext,
				Ciphertext.encrypt(pk, 1n).ciphertext,
			);
			const value = 100n + (200n << 16n) + (3n << 32n) + (1n << 48n);
			const collapsed = amount.collapse();
			const proof = collapsed.proveDecryption(DST, sk, pk, value);
			expect(collapsed.verifyDecryption(DST, pk, value, proof)).toBe(true);
			expect(collapsed.verifyDecryption(DST, pk, value + 1n, proof)).toBe(false);
		});
	});

	it('EncryptedAmount.decrypt reassembles limbs', () => {
		const [pk, sk] = generateKeyPair();
		const amount = new EncryptedAmount(
			Ciphertext.encrypt(pk, 100n).ciphertext,
			Ciphertext.encrypt(pk, 200n).ciphertext,
			Ciphertext.encrypt(pk, 3n).ciphertext,
			Ciphertext.encrypt(pk, 1n).ciphertext,
		);
		const result = amount.decrypt(sk, table);
		expect(result).toEqual(100n + (200n << 16n) + (3n << 32n) + (1n << 48n));
	});

	it('fromBcs roundtrip decrypts correctly', () => {
		const [pk, sk] = generateKeyPair();
		const { ciphertext } = Ciphertext.encrypt(pk, 42n);
		const raw = {
			ciphertext: { bytes: Array.from(ciphertext.ciphertext.toBytes()) },
			decryption_handle: { bytes: Array.from(ciphertext.decryptionHandle.toBytes()) },
		};
		const c2 = Ciphertext.fromBcs(raw);
		expect(c2.decrypt(sk, table)).toEqual(42n);
	});

	describe('noble extended-point internals (decrypt depends on these)', () => {
		// `cosetX` / `computeTableEntries` in twisted_elgamal.ts read noble's
		// PRIVATE extended-point representation (`.ep` with bigint X/Y/Z/T) and
		// build torsion points via the extended-point constructor. These tests
		// pin that internal contract so a `@noble/curves` upgrade that changes it
		// fails here (naming the cause) instead of as opaque decrypt failures.
		it('exposes the .ep extended-point layout the code relies on', () => {
			const ep = (ristretto255.Point.BASE as { ep?: Record<string, unknown> }).ep;
			expect(ep).toBeDefined();
			for (const f of ['X', 'Y', 'Z', 'T']) {
				expect(typeof ep![f]).toBe('bigint');
			}
			// The torsion points are built as `new EP(X, Y, Z, T)`; the identity is
			// (0, 1, 1, 0) in extended coords and must be addable to a real point.
			const EP = (ep as { constructor: new (...a: bigint[]) => unknown }).constructor;
			const identity = new EP(0n, 1n, 1n, 0n) as { add?: unknown };
			expect(() => (ep as { add: (o: unknown) => unknown }).add(identity)).not.toThrow();
		});

		it('decrypts a swept range, exercising cosetX across many representatives', () => {
			// Small table (size 256) so most values force several giant steps,
			// and every lookup runs cosetX over the torsion coset.
			const small = DiscreteLogTable.create(8);
			const [pk, sk] = generateKeyPair();
			for (const m of [0n, 1n, 7n, 255n, 256n, 257n, 511n, 1000n, 5000n]) {
				const { ciphertext } = Ciphertext.encrypt(pk, m);
				expect(ciphertext.decrypt(sk, small)).toEqual(m);
			}
		});
	});

	describe('DiscreteLogTable', () => {
		it('create and fromEntries produce equivalent tables', () => {
			const [pk, sk] = generateKeyPair();
			const entries = computeTableEntries(16);
			const table2 = DiscreteLogTable.fromEntries(16, entries);
			const { ciphertext } = Ciphertext.encrypt(pk, 12345n);
			expect(ciphertext.decrypt(sk, table)).toEqual(ciphertext.decrypt(sk, table2));
		});

		it('handles different numBits', () => {
			const smallTable = DiscreteLogTable.create(8);
			const [pk, sk] = generateKeyPair();
			const { ciphertext } = Ciphertext.encrypt(pk, 200n);
			expect(ciphertext.decrypt(sk, smallTable)).toEqual(200n);
		});
	});

	describe('MultiRecipientEncryption', () => {
		it('single recipient: decrypt recovers plaintext', () => {
			const [pk, sk] = generateKeyPair();
			const value = 42n;
			const blinding = randomScalar();
			const ct = MultiRecipientEncryption.encrypt([pk], value, blinding);
			expect(ct.decrypt(0, sk, table)).toEqual(value);
		});

		it('multiple recipients: each recovers same plaintext', () => {
			const [pk0, sk0] = generateKeyPair();
			const [pk1, sk1] = generateKeyPair();
			const [pk2, sk2] = generateKeyPair();
			const value = 1337n;
			const blinding = randomScalar();
			const ct = MultiRecipientEncryption.encrypt([pk0, pk1, pk2], value, blinding);
			expect(ct.decrypt(0, sk0, table)).toEqual(value);
			expect(ct.decrypt(1, sk1, table)).toEqual(value);
			expect(ct.decrypt(2, sk2, table)).toEqual(value);
		});

		it('all recipients share the same commitment', () => {
			const [pk0] = generateKeyPair();
			const [pk1] = generateKeyPair();
			const blinding = randomScalar();
			const ct = MultiRecipientEncryption.encrypt([pk0, pk1], 99n, blinding);
			// Each recipient pairs the single shared commitment with their own handle.
			const c0 = new Ciphertext(ct.commitment, ct.decryptionHandles[0]);
			const c1 = new Ciphertext(ct.commitment, ct.decryptionHandles[1]);
			expect(c0.ciphertext.equals(c1.ciphertext)).toBe(true);
		});

		it('decryption handles differ per recipient', () => {
			const [pk0] = generateKeyPair();
			const [pk1] = generateKeyPair();
			const blinding = randomScalar();
			const ct = MultiRecipientEncryption.encrypt([pk0, pk1], 7n, blinding);
			expect(ct.decryptionHandles[0].equals(ct.decryptionHandles[1])).toBe(false);
		});

		it('recipient cannot decrypt a slot not meant for them', () => {
			const [pk0] = generateKeyPair();
			const [, sk1] = generateKeyPair();
			const value = 55n;
			const blinding = randomScalar();
			const ct = MultiRecipientEncryption.encrypt([pk0], value, blinding);
			const skInv = ristretto255.Point.Fn.inv(sk1);
			const decrypted = ct.commitment.subtract(ct.decryptionHandles[0].multiply(skInv));
			expect(decrypted.equals(H.multiply(value))).toBe(false);
		});
	});
});
