// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bytesToHex, numberToBytesLE } from '@noble/curves/utils.js';
import { describe, expect, it } from 'vitest';

import { fiatShamirChallenge } from '../../src/helpers.js';
import { challengeDdh, challengeElgamal, DdhNizk } from '../../src/nizk.js';
import { G, H, mul, randomScalar } from '../../src/ristretto255.js';
import { Ciphertext } from '../../src/twisted_elgamal.js';

const dst = new Uint8Array(38);

describe('nizk', () => {
	it('ddh nizk round trip (two-pair Chaum-Pedersen)', () => {
		const x = 12345n;

		const xG = G.multiply(x);
		const xH = H.multiply(x);

		const nizk = DdhNizk.prove(dst, x, [G, H], [xG, xH]);
		expect(nizk.verify(dst, [G, H], [xG, xH])).toBeTruthy();
	});

	it('ddh nizk batch round trip (five-pair re-key relation)', () => {
		const w = randomScalar();
		// Five independent bases; each image is `w * base` (the re-key relation).
		const bases = Array.from({ length: 5 }, (_, i) => mul(G, BigInt(i + 1) * 100n));
		const images = bases.map((b) => mul(b, w));

		const proof = DdhNizk.prove(dst, w, bases, images);
		expect(proof.verify(dst, bases, images)).toBeTruthy();

		// A single wrong image breaks verification.
		const badImages = [...images];
		badImages[2] = G;
		expect(proof.verify(dst, bases, badImages)).toBeFalsy();
	});

	it('ddh nizk multi-witness batch round trip (auditor two-limb fold)', () => {
		// Shared bases (receiver key + auditor keys); two independent witnesses (the two u32 limbs).
		const bases = Array.from({ length: 4 }, (_, i) => mul(G, BigInt(i + 3) * 7n));
		const witnesses = [randomScalar(), randomScalar()];
		const imagesPerWitness = witnesses.map((w) => bases.map((b) => mul(b, w)));

		const proof = DdhNizk.proveBatch(dst, witnesses, bases, imagesPerWitness);
		expect(proof.verifyBatch(dst, bases, imagesPerWitness)).toBeTruthy();

		// Tampering with any witness's image at any base breaks verification.
		const badImages = imagesPerWitness.map((imgs) => [...imgs]);
		badImages[1][0] = G;
		expect(proof.verifyBatch(dst, bases, badImages)).toBeFalsy();
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

	// Pinned to the same constants as Move's `nizk::challenge_transcript_regression`, locking the
	// full per-proof transcript layout (not just the hash primitive) across the two languages.
	it('challenge transcripts match the on-chain pinned constants', () => {
		const dst21 = Uint8Array.from({ length: 21 }, (_, i) => i);
		const points = Array.from({ length: 6 }, (_, i) => mul(G, BigInt((i + 1) * 11)));

		const cDdh = challengeDdh(
			dst21,
			[points[0], points[1]],
			[points[2], points[3]],
			[points[4], points[5]],
		);
		expect(bytesToHex(numberToBytesLE(cDdh, 32))).toBe(
			'b5baa7c858c0eb740d9c38cc273f2062998dad57a798fa00e78cc33b4ba54200',
		);

		const encryptions = [
			new Ciphertext(points[0], points[1]),
			new Ciphertext(points[2], points[3]),
		];
		const cEg = challengeElgamal(dst21, points[4], encryptions, points[5], points[0]);
		expect(bytesToHex(numberToBytesLE(cEg, 32))).toBe(
			'bfc70a5eb7a3d6ff45c7f259078b46d3d1a1cd1c8f9affe06b3d37bb40548900',
		);
	});
});
