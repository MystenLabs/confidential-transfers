// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { beforeAll, describe, expect, it } from 'vitest';

import { getBulletproofs, type Bulletproofs } from '../../src/bp.js';
import { ContraInternalError } from '../../src/error.js';
import { randomScalar } from '../../src/ristretto255.js';

let bp: Bulletproofs;

const DST = new Uint8Array([1, 2, 3, 4]);

beforeAll(async () => {
	bp = await getBulletproofs();
});

describe('batchRangeProver', () => {
	it('produces one 32-byte commitment per input', () => {
		const values = [10n, 200n, 3000n, 40000n];
		const blindings = values.map(() => randomScalar());
		const { proof, commitments } = bp.batchRangeProver(values, blindings, 32, DST);
		expect(proof).toBeInstanceOf(Uint8Array);
		expect(proof.length).toBeGreaterThan(0);
		expect(commitments).toHaveLength(values.length);
		for (const c of commitments) expect(c.toBytes().length).toBe(32);
	});

	it('rejects non-power-of-2 batch size', () => {
		const values = [1n, 2n, 3n];
		const blindings = values.map(() => randomScalar());
		expect(() => bp.batchRangeProver(values, blindings, 32, DST)).toThrow(ContraInternalError);
	});

	it('rejects mismatched values/blindings', () => {
		expect(() => bp.batchRangeProver([1n, 2n], [randomScalar()], 32, DST)).toThrow(
			ContraInternalError,
		);
	});
});

describe('verifyBatchRangeProof', () => {
	it('accepts a valid proof', () => {
		const values = [10n, 200n, 3000n, 40000n];
		const blindings = values.map(() => randomScalar());
		const { proof, commitments } = bp.batchRangeProver(values, blindings, 32, DST);
		expect(bp.verifyBatchRangeProof(proof, commitments, 32, DST)).toBe(true);
	});

	it('rejects a tampered proof', () => {
		const values = [1n, 2n, 3n, 4n];
		const blindings = values.map(() => randomScalar());
		const { proof, commitments } = bp.batchRangeProver(values, blindings, 16, DST);
		const tampered = new Uint8Array(proof);
		tampered[0] ^= 1;
		expect(bp.verifyBatchRangeProof(tampered, commitments, 16, DST)).toBe(false);
	});

	it('rejects wrong bit size', () => {
		const values = [1n, 2n, 3n, 4n];
		const blindings = values.map(() => randomScalar());
		const { proof, commitments } = bp.batchRangeProver(values, blindings, 16, DST);
		expect(bp.verifyBatchRangeProof(proof, commitments, 32, DST)).toBe(false);
	});

	it('rejects mismatched commitments', () => {
		const values = [1n, 2n, 3n, 4n];
		const blindings = values.map(() => randomScalar());
		const { proof, commitments } = bp.batchRangeProver(values, blindings, 16, DST);
		const wrongBlindings = values.map(() => randomScalar());
		const { commitments: wrongCommitments } = bp.batchRangeProver(values, wrongBlindings, 16, DST);
		expect(bp.verifyBatchRangeProof(proof, wrongCommitments, 16, DST)).toBe(false);
	});

	it('rejects a proof verified under a different DST', () => {
		const values = [1n, 2n, 3n, 4n];
		const blindings = values.map(() => randomScalar());
		const { proof, commitments } = bp.batchRangeProver(values, blindings, 16, DST);
		const otherDst = new Uint8Array([9, 9, 9, 9]);
		expect(bp.verifyBatchRangeProof(proof, commitments, 16, otherDst)).toBe(false);
	});
});
