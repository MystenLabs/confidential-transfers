// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Register the message handler synchronously, BEFORE doing any async
// work. The ts-sdk import chain hits a top-level `await` (WASM init in
// bp.ts); if we imported at module load, `self.onmessage` would only be
// set after that await resolved, by which time the parent's
// `worker.postMessage(...)` has already been dispatched and dropped.
self.onmessage = async (e: MessageEvent<{ numBits: number }>) => {
	const { computeTableEntries } = await import('ts-sdk');
	const entries = computeTableEntries(e.data.numBits);
	self.postMessage(entries, { transfer: [entries.buffer] });
};
