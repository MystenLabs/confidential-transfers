// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Client-side input validation that rejects a batch before any network access
 * or proof construction.
 */

import { SuiGrpcClient } from '@mysten/sui/grpc';
import { describe, expect, it } from 'vitest';

import { contra } from '../../src/client.js';
import { InvalidArgumentError } from '../../src/error.js';
import { randomScalar } from '../../src/ristretto255.js';
import { DiscreteLogTable } from '../../src/twisted_elgamal.js';

const SENDER = `0x${'11'.repeat(32)}`;
const RECEIVER = `0x${'22'.repeat(32)}`;
const TOKEN_TYPE = `0x${'33'.repeat(32)}::test_token::TEST_TOKEN`;

const client = new SuiGrpcClient({ network: 'devnet', baseUrl: 'http://127.0.0.1:1' }).$extend(
	contra({
		packageConfig: {
			packageId: `0x${'44'.repeat(32)}`,
			accountRegistryId: `0x${'55'.repeat(32)}`,
			tokenRegistryId: `0x${'66'.repeat(32)}`,
		},
		table: DiscreteLogTable.create(1),
	}),
);

const tokenAccount = client.contra.tokenAccount({
	address: SENDER,
	tokenType: TOKEN_TYPE,
	privateKey: randomScalar(),
});

describe('transferBatch amount validation', () => {
	// `intoLimbs` reduces mod 2^64, so an unvalidated out-of-range amount would encrypt a
	// different value than the one checked against the spendable balance.
	it.each([
		['negative', -100n],
		['2^64', 1n << 64n],
		['above 2^64', (1n << 64n) + 7n],
	])('rejects a %s amount', async (_label, amount) => {
		await expect(
			client.contra.transferBatch({
				tokenAccount,
				recipients: [{ receiverAddress: RECEIVER, amount }],
			}),
		).rejects.toThrow(InvalidArgumentError);
	});

	it('rejects a batch whose out-of-range amounts cancel in the total', async () => {
		await expect(
			client.contra.transferBatch({
				tokenAccount,
				recipients: [
					{ receiverAddress: RECEIVER, amount: (1n << 64n) + 7n },
					{ receiverAddress: `0x${'77'.repeat(32)}`, amount: -(1n << 64n) + 50n },
				],
			}),
		).rejects.toThrow(InvalidArgumentError);
	});

	// A zero-value leg is legitimate: the chain charges a deposit term per ciphertext, not per
	// unit of value, so it is only rejected for `wrap` and `unwrap`.
	it.each([
		['zero', 0n],
		['positive', 100n],
	])('accepts a %s amount (failing later, on network access)', async (_label, amount) => {
		await expect(
			client.contra.transferBatch({
				tokenAccount,
				recipients: [{ receiverAddress: RECEIVER, amount }],
			}),
		).rejects.not.toThrow(InvalidArgumentError);
	});
});
