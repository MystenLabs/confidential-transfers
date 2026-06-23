// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import { ContraAuditor } from '../../src/auditor.js';
import { limbsToScalar, scalarToLimbs } from '../../src/nizk.js';
import { G, GROUP_ORDER, mul } from '../../src/ristretto255.js';
import {
	DiscreteLogTable,
	generateKeyPair,
	MultiRecipientEncryption,
	type PrivateKey,
} from '../../src/twisted_elgamal.js';
import type {
	ContraAuditorOptions,
	ContraPackageConfig,
	VerifiedKeyEncryption,
} from '../../src/types.js';

const ZERO_ADDR = '0x0000000000000000000000000000000000000000000000000000000000000000';
const DUMMY_CONFIG: ContraPackageConfig = {
	packageId: ZERO_ADDR,
	accountRegistryId: ZERO_ADDR,
	tokenRegistryId: ZERO_ADDR,
};

describe('ContraAuditor.recoverPrivateKey', () => {
	const table = DiscreteLogTable.create(20);
	const [auditorPk, auditorSk] = generateKeyPair();

	function escrow(keyValue: bigint): VerifiedKeyEncryption {
		const ciphertext = scalarToLimbs(keyValue).map((limb, i) =>
			MultiRecipientEncryption.encrypt([auditorPk], limb, BigInt((i + 1) * 7)),
		);
		return { ciphertext, version: 0 };
	}

	function auditorFor(): ContraAuditor {
		const options: ContraAuditorOptions = {
			suiClient: {} as ContraAuditorOptions['suiClient'],
			packageConfig: DUMMY_CONFIG,
			tokenType: `${ZERO_ADDR}::test::T`,
			table,
			auditorKeyForVersion: new Map<number, { index: number; privateKey: PrivateKey }>([
				[0, { index: 0, privateKey: auditorSk }],
			]),
		};
		return new ContraAuditor(options);
	}

	it('recovers a canonical escrowed key unchanged', () => {
		const sk = 1234567890n;
		expect(auditorFor().recoverPrivateKey(escrow(sk), mul(G, sk))).toBe(sk);
	});

	it('recovers the canonical key from a non-canonical alias X = sk + q', () => {
		const sk = 1234567890n;
		const alias = sk + GROUP_ORDER;

		// Sanity: the alias is a distinct, non-canonical 256-bit value whose limbs are all valid u32.
		expect(alias).toBeGreaterThanOrEqual(GROUP_ORDER);
		const limbs = scalarToLimbs(alias);
		expect(limbs.every((l) => l < 1n << 32n)).toBe(true);
		expect(limbsToScalar(limbs)).toBe(alias);

		// The escrowed value is the alias, but the account public key is the canonical `sk * G`.
		expect(auditorFor().recoverPrivateKey(escrow(alias), mul(G, sk))).toBe(sk);
	}, 30000);

	it('rejects a key encryption that does not match the account public key', () => {
		const donorSk = 1234567890n;
		const victimSk = 9876543210n;
		expect(() => auditorFor().recoverPrivateKey(escrow(donorSk), mul(G, victimSk))).toThrow(
			/does not match the account public key/,
		);
	});
});
