// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bytesToHex, numberToBytesLE } from '@noble/curves/utils.js';
import { describe, expect, it } from 'vitest';

import { fiatShamirChallenge } from '../../src/helpers.js';
import { DdhTupleNizk } from '../../src/nizk.js';
import { G, H } from '../../src/ristretto255.js';

const dst = new Uint8Array(38);

describe('nizk', () => {
	it('ddh nizk round trip', () => {
		const x = 12345n;

		const xG = G.multiply(x);
		const xH = H.multiply(x);

		const nizk = DdhTupleNizk.prove(dst, x, G, H, xG, xH);
		expect(nizk.verify(dst, G, H, xG, xH)).toBeTruthy();
	});

	// Pinned to the same constant as Move's `nizk::fiat_shamir_challenge_regression`, so the two
	// BCS transcripts cannot silently diverge (which would break on-chain proof verification).
	it('fiat-shamir challenge matches the on-chain BCS transcript', () => {
		const part0 = Uint8Array.from({ length: 21 }, (_, i) => i);
		const part1 = Uint8Array.from({ length: 32 }, (_, i) => i);
		const c = fiatShamirChallenge([part0, part1]);
		expect(bytesToHex(numberToBytesLE(c, 32))).toBe(
			'af00c4976049ed81805c76d3c5ba7cfaeb1550e44f5978cffb12b285a5e25a00',
		);
	});
});
