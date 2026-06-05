// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';

import { InvalidArgumentError } from './error.js';

/**
 * Structural interface for a ristretto255 point, covering the subset of the
 * `@noble/curves` `_RistrettoPoint` API that this SDK uses. A dedicated
 * interface is used (rather than `InstanceType<typeof ristretto255.Point>`)
 * because the underlying class has protected members that can't appear in
 * emitted `.d.ts` files.
 */
export interface RistrettoPoint {
	readonly x: bigint;
	readonly y: bigint;
	add(other: RistrettoPoint): RistrettoPoint;
	subtract(other: RistrettoPoint): RistrettoPoint;
	/** Constant-time, rejects 0 as input. */
	multiply(scalar: bigint): RistrettoPoint;
	/** Not constant-time (faster), accepts 0 as input. */
	multiplyUnsafe(scalar: bigint): RistrettoPoint;
	double(): RistrettoPoint;
	equals(other: RistrettoPoint): boolean;
	toBytes(): Uint8Array;
	/**
	 * Register a wNAF window size for this point so subsequent `multiply`
	 * / `multiplyUnsafe` calls use a precomputed table. Without this the
	 * default `W = 1` falls back to a plain double-and-add ladder.
	 */
	precompute(windowSize?: number, isLazy?: boolean): RistrettoPoint;
}

/** The ristretto255 prime-order group's standard base point. */
export const G: RistrettoPoint = ristretto255.Point.BASE;

/**
 * A second, independent ristretto255 generator used as the blinding
 * base point in Pedersen commitments and twisted ElGamal encryptions.
 * Matches the on-chain `contra::twisted_elgamal::h()` constant which
 * was derived via fastcrypto's `hash_to_curve("fastcrypto-blinding-gen-01")`.
 *
 * We reproduce the derivation here using noble's lower-level primitives:
 * `SHA-512(input)` followed by `deriveToCurve` (the Elligator 2 map).
 * Noble's higher-level `hashToCurve` cannot be used because it applies
 * RFC 9380 `expand_message_xmd` with a DST, whereas fastcrypto hashes
 * the raw input with plain SHA-512 — producing different 64-byte
 * intermediates and therefore a different point.
 */
export const H: RistrettoPoint = ristretto255_hasher.deriveToCurve!(
	sha512(new TextEncoder().encode('fastcrypto-blinding-gen-01')),
);

// Windowed wNAF table for `H`; matches noble's `Point.BASE.precompute(8)`.
H.precompute(8);

/** The ristretto255 identity (zero) point. */
export const ZERO: RistrettoPoint = ristretto255.Point.ZERO;

/**
 * Constant-time scalar multiplication `scalar * point` that accepts `0`.
 * Leaks information in case of 0 input.
 *
 * Out-of-range scalars (negative or `>= group order`) throw.
 */
export function mul(point: RistrettoPoint, scalar: bigint): RistrettoPoint {
	return scalar === 0n ? ZERO : point.multiply(scalar);
}

/**
 * Variable-time scalar multiplication `scalar * point`; accepts `0`.
 * NOT constant-time, its purpose is speed.
 */
export function mulUnsafe(point: RistrettoPoint, scalar: bigint): RistrettoPoint {
	return point.multiplyUnsafe(scalar);
}

/**
 * Deserialize a compressed ristretto255 point from its on-chain BCS
 * encoding.
 */
export function pointFromBcs(element: { bytes: number[] }): RistrettoPoint {
	try {
		return ristretto255.Point.fromBytes(Uint8Array.from(element.bytes));
	} catch (cause) {
		throw new InvalidArgumentError(
			`not a canonical compressed ristretto255 point: ${cause instanceof Error ? cause.message : String(cause)}`,
		);
	}
}

/** Generate a uniformly random scalar. */
export function randomScalar(): bigint {
	const seed = new Uint8Array(32);
	crypto.getRandomValues(seed);
	return ristretto255_hasher.hashToScalar(seed);
}

/** Assert that `s` is a usable secret scalar, i.e. `1 <= s < group order`. */
export function assertNonZeroScalar(s: bigint): void {
	const Fn = ristretto255.Point.Fn;
	if (s === 0n || !Fn.isValid(s))
		throw new InvalidArgumentError(
			`scalar must be a non-zero canonical element of the ristretto255 scalar field`,
		);
}

/** Sum scalars in the ristretto255 scalar field, reducing modulo the group order. */
export function addScalars(scalars: bigint[]): bigint {
	const Fn = ristretto255.Point.Fn;
	return scalars.reduce((acc, s) => Fn.add(acc, s), 0n);
}

/**
 * Serialize a ristretto255 scalar as 32 little-endian bytes.
 * Throws if `s` is not a canonical element of the ristretto255 scalar field.
 */
export function scalarToBytes(s: bigint): Uint8Array {
	const Fn = ristretto255.Point.Fn;
	if (!Fn.isValid(s))
		throw new InvalidArgumentError(
			`scalar ${s} is not a canonical element of the ristretto255 scalar field`,
		);
	return Fn.toBytes(s);
}
