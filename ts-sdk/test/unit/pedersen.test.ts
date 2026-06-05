// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import { PedersenCommitment } from '../../src/pedersen.js';

describe('pedersen', () => {
	it('commitment round trip', () => {
		let value = 42n;
		let [commitment, blinding] = PedersenCommitment.commit(value);
		expect(commitment.verify(value, blinding)).toBeTruthy();
	});
});
