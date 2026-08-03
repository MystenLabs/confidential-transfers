// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ristretto255 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';

import { ContraAuditor } from '../../src/auditor.js';
import { mul, randomScalar, type RistrettoPoint } from '../../src/ristretto255.js';
import {
	Ciphertext,
	DiscreteLogTable,
	EncryptedAmount,
	generateKeyPair,
} from '../../src/twisted_elgamal.js';

/**
 * Build the per-transfer auditor material for a single receiver amount, mirroring the SDK's
 * `buildAuditorData`: the receiver-keyed `EncryptedAmount` and the two u32-limb auditor handles
 * `D̃_k = ρ̃_k · auditorPk`, `ρ̃_k = ρ_{2k} + 2^16 ρ_{2k+1}`.
 */
function buildTransfer(
	receiverPk: RistrettoPoint,
	auditorPk: RistrettoPoint,
	amount: bigint,
): { ea: EncryptedAmount; handles: RistrettoPoint[] } {
	const shift = 1n << 16n;
	const limbValues = [
		amount & 0xffffn,
		(amount >> 16n) & 0xffffn,
		(amount >> 32n) & 0xffffn,
		(amount >> 48n) & 0xffffn,
	];
	const blindings = limbValues.map(() => randomScalar());
	const limbs = limbValues.map(
		(v, j) => Ciphertext.encryptWithBlinding(receiverPk, v, blindings[j]).ciphertext,
	);
	const ea = new EncryptedAmount(limbs[0], limbs[1], limbs[2], limbs[3]);
	const rho0 = ristretto255.Point.Fn.create(blindings[0] + shift * blindings[1]);
	const rho1 = ristretto255.Point.Fn.create(blindings[2] + shift * blindings[3]);
	return { ea, handles: [mul(auditorPk, rho0), mul(auditorPk, rho1)] };
}

describe('ContraAuditor.decryptTransferAmount', () => {
	const table = DiscreteLogTable.create(16);
	const [auditorPk, auditorSk] = generateKeyPair();
	const [receiverPk] = generateKeyPair();

	function auditorFor(): ContraAuditor {
		return new ContraAuditor({ tokenType: '0x2::sui::SUI', privateKey: auditorSk, table });
	}

	it('recovers a small amount from the transfer commitments and handles', () => {
		const amount = 12345n;
		const { ea, handles } = buildTransfer(receiverPk, auditorPk, amount);
		expect(auditorFor().decryptTransferAmount(ea, handles)).toBe(amount);
	});

	it('recovers an amount spanning all four limbs (>2^32)', () => {
		const amount = (7n << 48n) | (3n << 32n) | (9n << 16n) | 42n;
		const { ea, handles } = buildTransfer(receiverPk, auditorPk, amount);
		expect(auditorFor().decryptTransferAmount(ea, handles)).toBe(amount);
	});

	it('throws when the transfer carried no auditor data', () => {
		const { ea } = buildTransfer(receiverPk, auditorPk, 1n);
		expect(() => auditorFor().decryptTransferAmount(ea, [])).toThrow(/2 auditor handles/);
	});

	it('a wrong auditor key does not recover the amount', () => {
		const amount = 500n;
		const { ea, handles } = buildTransfer(receiverPk, auditorPk, amount);
		const [, wrongSk] = generateKeyPair();
		const wrongAuditor = new ContraAuditor({
			tokenType: '0x2::sui::SUI',
			privateKey: wrongSk,
			table,
		});
		// The wrong key yields a different point; if it decrypts at all it is not `amount`.
		let recovered: bigint | undefined;
		try {
			recovered = wrongAuditor.decryptTransferAmount(ea, handles);
		} catch {
			recovered = undefined;
		}
		expect(recovered).not.toBe(amount);
	});
});
