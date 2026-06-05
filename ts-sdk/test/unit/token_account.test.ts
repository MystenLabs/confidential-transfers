// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import { PROTOCOL_VERIFIED_DEC } from '../../src/helpers.js';
import { TokenAccount } from '../../src/token_account.js';
import { Ciphertext, DiscreteLogTable } from '../../src/twisted_elgamal.js';
import type { ContraPackageConfig } from '../../src/types.js';

describe('TokenAccount.decryptWithProof', () => {
	const table = DiscreteLogTable.create(16);
	const ZERO_ADDR = '0x0000000000000000000000000000000000000000000000000000000000000000';
	const address = ZERO_ADDR;
	const tokenType = `${ZERO_ADDR}::test::T`;
	const DUMMY_CONFIG: ContraPackageConfig = {
		packageId: ZERO_ADDR,
		accountRegistryId: ZERO_ADDR,
		tokenRegistryId: ZERO_ADDR,
	};

	it('Ciphertext: returned value matches plain decryption and proof verifies', () => {
		const account = new TokenAccount(address, tokenType, DUMMY_CONFIG);
		const m = 9876n;
		const { ciphertext } = Ciphertext.encrypt(account.publicKey, m);

		const { value, proof } = account.decryptWithProof(ciphertext, table);

		expect(value).toEqual(m);
		expect(
			ciphertext.verifyDecryption(
				account.dst(PROTOCOL_VERIFIED_DEC),
				account.publicKey,
				value,
				proof,
			),
		).toBe(true);
	});

	it('Ciphertext: proof rejects a tampered claimed value', () => {
		const account = new TokenAccount(address, tokenType, DUMMY_CONFIG);
		const { ciphertext } = Ciphertext.encrypt(account.publicKey, 42n);

		const { value, proof } = account.decryptWithProof(ciphertext, table);

		expect(
			ciphertext.verifyDecryption(
				account.dst(PROTOCOL_VERIFIED_DEC),
				account.publicKey,
				value + 1n,
				proof,
			),
		).toBe(false);
	});

	it("a third party cannot forge a decryption proof without the account's sk", () => {
		const owner = new TokenAccount(address, tokenType, DUMMY_CONFIG);
		const attacker = new TokenAccount(address, tokenType, DUMMY_CONFIG);
		const { ciphertext } = Ciphertext.encrypt(owner.publicKey, 1000n);

		// Attacker tries to produce a proof under the owner's pk using
		// the attacker's own sk — the resulting proof should not verify
		// because the attacker does not know the discrete log of owner.publicKey.
		const ownerSid = owner.dst(PROTOCOL_VERIFIED_DEC);
		const forged = ciphertext.proveDecryption(
			ownerSid,
			attacker.privateKey,
			owner.publicKey,
			1000n,
		);
		expect(ciphertext.verifyDecryption(ownerSid, owner.publicKey, 1000n, forged)).toBe(false);
	});
});
