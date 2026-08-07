// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ristretto255 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';

import { ContraAuditor, type DecodedTransferEvent } from '../../src/auditor.js';
import { mul, randomScalar, type RistrettoPoint } from '../../src/ristretto255.js';
import {
	Ciphertext,
	DiscreteLogTable,
	EncryptedAmount,
	generateKeyPair,
} from '../../src/twisted_elgamal.js';

const bcsPoint = (p: RistrettoPoint) => ({ bytes: Array.from(p.toBytes()) });
const bcsLimb = (c: Ciphertext) => ({
	ciphertext: bcsPoint(c.ciphertext),
	decryption_handle: bcsPoint(c.decryptionHandle),
});

/**
 * Build a decoded `TransferEvent` for a single receiver amount, mirroring the SDK's `buildAuditorData`:
 * the receiver-keyed `EncryptedAmount` and the two u32-limb auditor handles `D̃_k = ρ̃_k · auditorPk`,
 * `ρ̃_k = ρ_{2k} + 2^16 ρ_{2k+1}`, packed into the fields `decryptTransferAmount` reads.
 */
function buildTransferEvent(
	receiverPk: RistrettoPoint,
	auditorPk: RistrettoPoint,
	amount: bigint,
): DecodedTransferEvent {
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
	return {
		encrypted_amount_receiver: {
			l0: bcsLimb(ea.l0),
			l1: bcsLimb(ea.l1),
			l2: bcsLimb(ea.l2),
			l3: bcsLimb(ea.l3),
		},
		auditor_decryption_handles: {
			handles: [bcsPoint(mul(auditorPk, rho0)), bcsPoint(mul(auditorPk, rho1))],
		},
		auditor_pk: { element: bcsPoint(auditorPk) },
	};
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
		expect(
			auditorFor().decryptTransferAmount(buildTransferEvent(receiverPk, auditorPk, amount)),
		).toBe(amount);
	});

	it('recovers an amount spanning all four limbs (>2^32)', () => {
		const amount = (7n << 48n) | (3n << 32n) | (9n << 16n) | 42n;
		expect(
			auditorFor().decryptTransferAmount(buildTransferEvent(receiverPk, auditorPk, amount)),
		).toBe(amount);
	});

	it('returns null when the transfer carried no auditor data', () => {
		const event = buildTransferEvent(receiverPk, auditorPk, 1n);
		event.auditor_decryption_handles = null;
		expect(auditorFor().decryptTransferAmount(event)).toBeNull();
	});

	it('throws when it holds no key matching the transfer auditor_pk', () => {
		const event = buildTransferEvent(receiverPk, auditorPk, 500n);
		const [, wrongSk] = generateKeyPair();
		const wrongAuditor = new ContraAuditor({
			tokenType: '0x2::sui::SUI',
			privateKeys: [wrongSk],
			table,
		});
		expect(() => wrongAuditor.decryptTransferAmount(event)).toThrow(/no private key matching/);
	});

	it('decrypts transfers under either key across a rotation', () => {
		const [oldPk, oldSk] = generateKeyPair();
		const [newPk, newSk] = generateKeyPair();
		const auditor = new ContraAuditor({
			tokenType: '0x2::sui::SUI',
			privateKeys: [oldSk, newSk],
			table,
		});
		// Matches each transfer's auditor_pk to the right held key.
		expect(auditor.decryptTransferAmount(buildTransferEvent(receiverPk, oldPk, 111n))).toBe(111n);
		expect(auditor.decryptTransferAmount(buildTransferEvent(receiverPk, newPk, 222n))).toBe(222n);
	});

	it('addKey extends the set of decryptable keys', () => {
		const [rotatedPk, rotatedSk] = generateKeyPair();
		const auditor = auditorFor();
		const event = buildTransferEvent(receiverPk, rotatedPk, 777n);
		expect(() => auditor.decryptTransferAmount(event)).toThrow(/no private key/);
		auditor.addKey(rotatedSk);
		expect(auditor.decryptTransferAmount(event)).toBe(777n);
	});
});
