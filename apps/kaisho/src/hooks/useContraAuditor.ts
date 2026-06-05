// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useSuiClient } from '@mysten/dapp-kit';
import { useEffect, useMemo, useState } from 'react';
import type { AuditorVersionEntry, ContraAuditor, DiscreteLogTable } from 'ts-sdk';

import { contraPackageConfig, createContraAuditor } from '../sdk';
import type { TokenConfig } from '../sdk';
import { getTablePromise } from './dlogTable';

/**
 * The auditor decrypts u32 limbs of the user's twisted ElGamal private
 * key (8 limbs total). With `numBits = 19` each limb finds its plaintext
 * within at most 2^13 giant-step iterations (≈8× faster than the default
 * 16-bit table) at the cost of a 4 MiB table that's built once per app
 * load in a web worker.
 */
const AUDITOR_TABLE_NUM_BITS = 19;

/**
 * Build a `ContraAuditor` from a `TokenConfig` plus a map from the
 * on-chain auditor `version` to this auditor's index and private key for
 * that version. Computes a dedicated 19-bit DLog table in a web worker
 * the first time this hook mounts; subsequent mounts reuse the cached
 * promise. Returns `null` until the table, config, and version map are
 * all ready.
 */
export function useContraAuditor(
	config: TokenConfig | undefined,
	tokenType: string | undefined,
	auditorKeyForVersion: Map<number, AuditorVersionEntry>,
): ContraAuditor | null {
	const suiClient = useSuiClient();
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
		if (!config || !tokenType || !table || auditorKeyForVersion.size === 0) return null;
		return createContraAuditor(
			suiClient,
			contraPackageConfig(config),
			tokenType,
			table,
			auditorKeyForVersion,
		);
	}, [suiClient, config, tokenType, table, auditorKeyForVersion]);
}
