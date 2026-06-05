// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { DiscreteLogTable } from 'ts-sdk';

/**
 * Per-`numBits` memoized promises for `DiscreteLogTable`s, built once
 * per app load in a web worker. The raw table size is `2^numBits * 8`
 * bytes (e.g. 512 KiB at 16 bits, 8 MiB at 20 bits). +1 bit doubles the
 * memory and halves the worst-case giant-step iterations, so different
 * call sites can pick different points on the curve.
 */
const tablePromises = new Map<number, Promise<DiscreteLogTable>>();

export function getTablePromise(numBits: number): Promise<DiscreteLogTable> {
	const cached = tablePromises.get(numBits);
	if (cached) return cached;
	const promise = new Promise<DiscreteLogTable>((resolve) => {
		const worker = new Worker(new URL('../workers/tableWorker.ts', import.meta.url), {
			type: 'module',
		});
		worker.onmessage = (e: MessageEvent<Uint32Array>) => {
			resolve(DiscreteLogTable.fromEntries(numBits, e.data));
			worker.terminate();
		};
		worker.postMessage({ numBits });
	});
	tablePromises.set(numBits, promise);
	return promise;
}
