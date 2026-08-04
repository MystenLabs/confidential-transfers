// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import type { ContraAuditor, DiscreteLogTable } from 'ts-sdk';

import { createContraAuditor } from '../sdk';
import type { TokenConfig } from '../sdk';
import { getTablePromise } from './dlogTable';

/**
 * Per-transfer auditing regroups a transfer's four u16 limbs into two u32 limbs, so the auditor
 * BSGS-decrypts up to 32-bit values. With `numBits = 19` each limb finds its plaintext within at
 * most 2^13 giant-step iterations (≈8× faster than the default 16-bit table) at the cost of a 4 MiB
 * table that's built once per app load in a web worker.
 */
const AUDITOR_TABLE_NUM_BITS = 19;

/**
 * Build a `ContraAuditor` from a `TokenConfig`, token type, and the token's auditor private key.
 * Computes a dedicated 19-bit DLog table in a web worker the first time this hook mounts; subsequent
 * mounts reuse the cached promise. Returns `null` until the table, config, token type, and key are
 * all ready.
 */
export function useContraAuditor(
	config: TokenConfig | undefined,
	tokenType: string | undefined,
	privateKey: bigint | null,
): ContraAuditor | null {
	const [table, setTable] = useState<DiscreteLogTable | null>(null);

	useEffect(() => {
		let cancelled = false;
		getTablePromise(AUDITOR_TABLE_NUM_BITS).then((t) => {
			if (!cancelled) setTable(t);
		});
		return () => {
			cancelled = true;
		};
	}, []);

	return useMemo(() => {
		if (!config || !tokenType || !table || privateKey === null) return null;
		return createContraAuditor(tokenType, privateKey, table);
	}, [config, tokenType, table, privateKey]);
}
