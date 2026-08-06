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
		return new ContraAuditor({ tokenType: '0x2::sui::SUI', privateKeys: [auditorSk], table });
	}

	it('recovers a small amount from the transfer commitments and handles', () => {
		const amount = 12345n;
		const { ea, handles } = buildTransfer(receiverPk, auditorPk, amount);
		expect(auditorFor().decryptTransferAmount(ea, handles, auditorPk)).toBe(amount);
	});

	it('recovers an amount spanning all four limbs (>2^32)', () => {
		const amount = (7n << 48n) | (3n << 32n) | (9n << 16n) | 42n;
		const { ea, handles } = buildTransfer(receiverPk, auditorPk, amount);
		expect(auditorFor().decryptTransferAmount(ea, handles, auditorPk)).toBe(amount);
	});

	it('throws when the transfer carried no auditor data', () => {
		const { ea } = buildTransfer(receiverPk, auditorPk, 1n);
		expect(() => auditorFor().decryptTransferAmount(ea, [], auditorPk)).toThrow(
			/2 auditor handles/,
		);
	});

	it('throws when it holds no key matching the transfer auditor_pk', () => {
		const { ea, handles } = buildTransfer(receiverPk, auditorPk, 500n);
		const [, wrongSk] = generateKeyPair();
		const wrongAuditor = new ContraAuditor({
			tokenType: '0x2::sui::SUI',
			privateKeys: [wrongSk],
			table,
		});
		expect(() => wrongAuditor.decryptTransferAmount(ea, handles, auditorPk)).toThrow(
			/no private key matching/,
		);
	});

	it('decrypts transfers under either key across a rotation', () => {
		const [oldPk, oldSk] = generateKeyPair();
		const [newPk, newSk] = generateKeyPair();
		const auditor = new ContraAuditor({
			tokenType: '0x2::sui::SUI',
			privateKeys: [oldSk, newSk],
			table,
		});
		const oldTransfer = buildTransfer(receiverPk, oldPk, 111n);
		const newTransfer = buildTransfer(receiverPk, newPk, 222n);
		// Matches each transfer's auditor_pk to the right held key.
		expect(auditor.decryptTransferAmount(oldTransfer.ea, oldTransfer.handles, oldPk)).toBe(111n);
		expect(auditor.decryptTransferAmount(newTransfer.ea, newTransfer.handles, newPk)).toBe(222n);
	});

	it('addKey extends the set of decryptable keys', () => {
		const [rotatedPk, rotatedSk] = generateKeyPair();
		const auditor = auditorFor();
		const { ea, handles } = buildTransfer(receiverPk, rotatedPk, 777n);
		expect(() => auditor.decryptTransferAmount(ea, handles, rotatedPk)).toThrow(/no private key/);
		auditor.addKey(rotatedSk);
		expect(auditor.decryptTransferAmount(ea, handles, rotatedPk)).toBe(777n);
	});
});
