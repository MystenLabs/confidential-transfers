// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { equalBytes } from '@noble/curves/utils.js';

import { G, H, mul, randomScalar, type RistrettoPoint } from './ristretto255.js';

export class PedersenCommitment {
	p!: RistrettoPoint;

	constructor(value: bigint, blinding: bigint) {
		this.p = mul(H, value).add(mul(G, blinding));
	}

	static commit(value: bigint): [PedersenCommitment, bigint] {
		const blinding = randomScalar();
		return [new PedersenCommitment(value, blinding), blinding];
	}

	verify(value: bigint, blinding: bigint): boolean {
		const expected = new PedersenCommitment(value, blinding);
		return equalBytes(this.p.toBytes(), expected.p.toBytes());
	}
}
