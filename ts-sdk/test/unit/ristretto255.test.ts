// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { G, H } from '../../src/ristretto255.js';

describe('ristretto255 generators', () => {
	// `H` is re-derived client-side from `hash_to_curve("fastcrypto-blinding-gen-01")`.
	// It MUST stay byte-identical to the on-chain `contra::twisted_elgamal::h()`
	// constant or every Pedersen commitment / ElGamal ciphertext the SDK builds
	// will fail on-chain verification. A `@noble/curves` change to `deriveToCurve`
	// (Elligator 2) or an edit to the seed string would break this silently, since
	// the encrypt/decrypt round-trip tests are internally consistent and wouldn't
	// catch a drift from the chain constant. This pins it.
	it('H matches the on-chain h() constant', () => {
		expect(bytesToHex(H.toBytes())).toBe(
			'34ce1477c14558178089500a39c864e0f607b3c1f41ab398400e4a9de6d2c446',
		);
	});

	// `G` is the ristretto255 standard base point; pinned for the same reason.
	it('G matches the on-chain g() constant', () => {
		expect(bytesToHex(G.toBytes())).toBe(
			'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
		);
	});
});
