// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Convenience wrappers around the WASM bindings for fastcrypto's batched
 * Bulletproof range proofs (`RangeProof::prove_batch` / `verify_batch`).
 *
 * The bindings live in the `@contra/bulletproofs-wasm` package, whose
 * `nodejs` / `web` builds must be generated first (`pnpm build:wasm` in that
 * package). The package's `exports` conditions select the right build per
 * environment: Node loads the synchronous `nodejs` build (so `init` is a
 * no-op), while bundlers pick the `web` build that needs an explicit `init`.
 */

import init, {
	batchRangeProof as wasmBatchRangeProof,
	verifyBatchRangeProof as wasmVerifyBatchRangeProof,
} from '@contra/bulletproofs-wasm';
import { ristretto255 } from '@noble/curves/ed25519.js';

import { ContraInternalError } from './error.js';
import { scalarToBytes, type RistrettoPoint } from './ristretto255.js';

/** Bit-length options supported by `fastcrypto::bulletproofs::Range`. */
export type RangeBits = 8 | 16 | 32 | 64;

/**
 * Bound, ready-to-call bulletproof functions returned by `getBulletproofs()`.
 * Synchronous — the WASM module is already initialized once the factory's
 * promise resolves, mirroring `@mysten/walrus-wasm`'s `getWasmBindings`.
 */
export interface Bulletproofs {
	/**
	 * Aggregate range proof that every `values[i]` lies in `[0, 2^bitSize)`.
	 *
	 * `values.length` must be a positive power of 2 and equal `blindings.length`.
	 * Blindings are ristretto255 scalars (use `randomScalar()` from
	 * `./ristretto255.js`). `dst` is the domain-separation tag bound into the
	 * proof transcript; the on-chain verifier
	 * (`rangeproofs::verify_bulletproofs_with_dst_ristretto255`) must be handed
	 * the same tag. Returns the serialized proof and the per-value Pedersen
	 * commitments in input order, compatible with fastcrypto.
	 */
	batchRangeProver(
		values: bigint[],
		blindings: bigint[],
		bitSize: RangeBits,
		dst: Uint8Array,
	): { proof: Uint8Array; commitments: RistrettoPoint[] };
	/**
	 * Verify an aggregate range proof that every `commitments[i]` encodes a
	 * value in `[0, 2^bitSize)` under the domain-separation tag `dst`. Compatible
	 * with fastcrypto's bulletproofs.
	 */
	verifyBatchRangeProof(
		proof: Uint8Array,
		commitments: RistrettoPoint[],
		bitSize: RangeBits,
		dst: Uint8Array,
	): boolean;
}

/** A bound `batchRangeProver` function, injected into the proof-building helpers. */
export type BatchRangeProver = Bulletproofs['batchRangeProver'];

/**
 * Initialize the bulletproofs WASM module and return bound, synchronous proof
 * functions. In Node the `nodejs` wasm-pack build loads synchronously (init is a no-op); in the
 * browser it fetches and instantiates the `.wasm` asset, with `moduleOrPath`
 * supplying an explicit URL/bytes when a bundler can't locate it.
 *
 * Not memoized here — callers cache the result.
 */
export async function getBulletproofs(
	moduleOrPath?: string | URL | Request | BufferSource,
): Promise<Bulletproofs> {
	await init({ module_or_path: moduleOrPath });

	return {
		batchRangeProver(values, blindings, bitSize, dst) {
			if (values.length !== blindings.length) {
				throw new ContraInternalError(
					`values.length must equal blindings.length (got ${values.length} and ${blindings.length})`,
				);
			}
			const n = values.length;
			if (n === 0 || (n & (n - 1)) !== 0) {
				throw new ContraInternalError(`values.length must be a positive power of 2 (got ${n})`);
			}

			const blindingBuf = new Uint8Array(n * 32);
			for (let i = 0; i < n; i++) {
				blindingBuf.set(scalarToBytes(blindings[i]), i * 32);
			}

			const { proof, commitments: flatCommitments } = wasmBatchRangeProof(
				new BigUint64Array(values),
				blindingBuf,
				bitSize,
				dst,
			);
			const commitments: RistrettoPoint[] = Array.from(chunks(flatCommitments, 32), (c) =>
				ristretto255.Point.fromBytes(c),
			);
			return { proof, commitments };
		},

		verifyBatchRangeProof(proof, commitments, bitSize, dst) {
			const commitmentBuf = new Uint8Array(commitments.length * 32);
			for (let i = 0; i < commitments.length; i++) {
				commitmentBuf.set(commitments[i].toBytes(), i * 32);
			}
			return wasmVerifyBatchRangeProof(proof, commitmentBuf, bitSize, dst);
		},
	};
}

function* chunks(bytes: Uint8Array, size: number): Generator<Uint8Array> {
	for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size);
}
