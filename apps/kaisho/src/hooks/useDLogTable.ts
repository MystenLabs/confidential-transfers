// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import type { DiscreteLogTable } from 'ts-sdk';

import { getTablePromise } from './dlogTable';

/** 16-bit DLog table covers 2^32 plaintexts (one u32 limb) — sufficient
 *  for end-user balance decryption. The auditor uses a larger table; see
 *  `useContraAuditor`. */
const DEFAULT_NUM_BITS = 16;

/**
 * Lazily-built `DiscreteLogTable` for decrypting user-side ciphertexts.
 * The promise is memoized across mounts so the table is computed at
 * most once per app load. Returns `null` until ready.
 */
export function useDLogTable(numBits: number = DEFAULT_NUM_BITS): DiscreteLogTable | null {
	const [table, setTable] = useState<DiscreteLogTable | null>(null);

	useEffect(() => {
		let cancelled = false;
		getTablePromise(numBits).then((t) => {
			if (!cancelled) setTable(t);
		});
		return () => {
			cancelled = true;
		};
	}, [numBits]);

	return table;
}
