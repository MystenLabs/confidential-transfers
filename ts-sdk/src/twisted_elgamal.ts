// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Field } from '@noble/curves/abstract/modular.js';
import { ristretto255 } from '@noble/curves/ed25519.js';

import { DecryptionFailedError, InvalidArgumentError } from './error.js';
import { DdhNizk } from './nizk.js';
import { PedersenCommitment } from './pedersen.js';
import {
	G,
	H,
	mul,
	mulUnsafe,
	pointFromBcs,
	randomScalar,
	ZERO,
	type RistrettoPoint,
} from './ristretto255.js';

/**
 * When enabled, the discrete-log table and decrypt routines emit timing
 * and size diagnostics to `console.log`. Off by default to keep host
 * applications quiet; toggle with {@link setDebugLogging}.
 */
let debugLogging = false;

/** Enable or disable diagnostic logging for table construction and decryption. */
export function setDebugLogging(enabled: boolean): void {
	debugLogging = enabled;
}

/** ed25519 base field for Montgomery batch inversion. */
const Fp = Field(2n ** 255n - 19n);

// NOTE: `cosetX` and `computeTableEntries` read noble's PRIVATE extended-point
// representation — `(point).ep` with bigint `X/Y/Z/T` fields — and build the
// torsion points below via the extended-point constructor `new EP(X, Y, Z, T)`.
// This is a deliberate performance optimization (extracting Edwards
// x-coordinates with a single batch inversion is ~70x faster than the public
// `toBytes()` per point when building the discrete-log table).

/** The 4 torsion points that form the ristretto equivalence kernel, in extended (X,Y,Z,T) coords. */
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const p = 2n ** 255n - 19n;
const EP = (ristretto255.Point.BASE as any).ep.constructor;
const TORSION_EPS = [
	new EP(0n, 1n, 1n, 0n), // identity
	new EP(0n, p - 1n, 1n, 0n), // (0, -1)
	new EP(SQRT_M1, 0n, 1n, 0n), // (√-1, 0)
	new EP(p - SQRT_M1, 0n, 1n, 0n), // (-√-1, 0)
];

/** The 4 Edwards .x coordinates of the ristretto equivalence class of `point`. */
function cosetX(point: RistrettoPoint): bigint[] {
	const ep = (point as any).ep;
	const shifted = TORSION_EPS.map((t: any) => ep.add(t));
	const invertedZs = Fp.invertBatch(shifted.map((s: any) => s.Z));
	return shifted.map((s: any, k) => Fp.mul(s.X, invertedZs[k]));
}

/** Key used for indexing the discrete-log table computed from the x-coordinate of the point. */
function key(x: bigint): number {
	return Number(x & 0xffffffffn);
}

export type PublicKey = RistrettoPoint;
export type PrivateKey = bigint;

export function generateKeyPair(): [PublicKey, PrivateKey] {
	const privateKey = randomScalar();
	const pk = mul(G, privateKey);
	return [pk, privateKey];
}

/**
 * Compute the raw table entries (truncated x-coordinates) for a given
 * numBits. This is a pure function that can run in a web worker. Returns
 * a Uint32Array where `entries[i]` is the truncated x-coordinate of `i*H`.
 * The result can be transferred to the main thread.
 */
export function computeTableEntries(numBits: number): Uint32Array {
	const start = performance.now();
	const tableSize = 2 ** numBits;
	const entries = new Uint32Array(tableSize);

	// Walk `i*H` in fixed-size chunks, extracting affine x-coordinates with one
	// batch inversion per chunk.
	const CHUNK = 1 << 12;
	const xs = new Array<bigint>(CHUNK);
	const zs = new Array<bigint>(CHUNK);
	let point = ZERO;
	for (let base = 0; base < tableSize; base += CHUNK) {
		const len = Math.min(CHUNK, tableSize - base);
		for (let k = 0; k < len; k++) {
			const ep = (point as any).ep;
			xs[k] = ep.X as bigint;
			zs[k] = ep.Z as bigint;
			point = point.add(H);
		}
		const invertedZs = Fp.invertBatch(len === CHUNK ? zs : zs.slice(0, len));
		for (let k = 0; k < len; k++) {
			entries[base + k] = key(Fp.mul(xs[k], invertedZs[k]));
		}
	}

	if (debugLogging) {
		const sizeBytes = tableSize * 4;
		const elapsed = performance.now() - start;
		console.log(
			`[computeTableEntries] computed in ${elapsed.toFixed(1)}ms | numBits=${numBits} | size=${(sizeBytes / 1024).toFixed(0)}KB`,
		);
	}
	return entries;
}

/**
 * Precomputed discrete-log table for ristretto255. Stores sequential
 * multiples of H keyed by truncated 4-byte Edwards x-coordinates,
 * with verification by scalar multiplication to guard against collisions.
 *
 * The table is held as two parallel, key-sorted `Uint32Array`s — `#keys`
 * (the truncated x-coordinates, ascending) and `#values` (the matching
 * baby-step index `i` such that `i*H` has that key).
 *
 * Decrypt searches by subtracting `2^numBits * H` (the giant step)
 * each iteration and checking the table. Small values (the common
 * case for u16 limbs) are found on the first lookup with no loop.
 *
 * Larger `numBits` makes decryption faster (fewer giant-step iterations
 * before a hit) but quadruples the table memory each bit: the table
 * holds `2^numBits` entries of 8 bytes each, so e.g. `numBits = 16`
 * is 512 KiB and `numBits = 24` is 128 MiB.
 */
export class DiscreteLogTable {
	readonly numBits: number;
	readonly tableSize: number;
	readonly giantStep: RistrettoPoint;
	#keys: Uint32Array;
	#values: Uint32Array;
	// Small internal cache to speed up lookups for repeated calls.
	static readonly MAX_CACHE_SIZE = 1024;
	#cache: Map<number, bigint>;

	private constructor(numBits: number, keys: Uint32Array, values: Uint32Array) {
		this.numBits = numBits;
		this.tableSize = 2 ** numBits;
		this.giantStep = mul(H, BigInt(this.tableSize));
		this.#keys = keys;
		this.#values = values;
		this.#cache = new Map();
	}

	/** Compute the table synchronously (convenience for tests / Node). */
	static create(numBits: number = 16): DiscreteLogTable {
		if (numBits > 32) {
			throw new InvalidArgumentError(`numBits must be <= 32 (got ${numBits})`);
		}
		return DiscreteLogTable.fromEntries(numBits, computeTableEntries(numBits));
	}

	/**
	 * Construct from pre-computed entries (e.g. from a web worker), where
	 * `entries[i]` is the truncated x-coordinate of `i*H`. Sorts the baby-step
	 * indices by their key into the parallel `#keys` / `#values` arrays.
	 */
	static fromEntries(numBits: number, entries: Uint32Array): DiscreteLogTable {
		const n = entries.length;

		const values = new Uint32Array(n);
		for (let i = 0; i < n; i++) values[i] = i;
		values.sort((a, b) => entries[a] - entries[b]);

		const keys = new Uint32Array(n);
		for (let j = 0; j < n; j++) keys[j] = entries[values[j]];

		if (debugLogging) {
			let collisions = 0;
			for (let j = 1; j < n; j++) if (keys[j] === keys[j - 1]) collisions++;
			const sizeBytes = n * (4 + 4);
			console.log(
				`[DiscreteLogTable] created | numBits=${numBits} | size=${(sizeBytes / 1024).toFixed(0)}KB | collisions=${collisions}`,
			);
		}
		return new DiscreteLogTable(numBits, keys, values);
	}

	/** Index of the first entry in `#keys` whose key is `>= target`. */
	#lowerBound(target: number): number {
		let lo = 0;
		let hi = this.#keys.length;
		while (lo < hi) {
			const mid = (lo + hi) >>> 1;
			if (this.#keys[mid] < target) lo = mid + 1;
			else hi = mid;
		}
		return lo;
	}

	/**
	 * Look up a point in the cache or precomputed table. Returns the
	 * baby-step value (table index) if matched, `undefined` otherwise.
	 * The caller adds the giant-step offset.
	 */
	lookup(point: RistrettoPoint): { value: bigint; cached: boolean } | undefined {
		// Cache key truncates to 32 bits; verify hits against the point.
		const cacheKey = key(point.x);
		const cached = this.#cache.get(cacheKey);
		if (cached !== undefined && mulUnsafe(H, cached).equals(point)) {
			return { value: cached, cached: true };
		}

		for (const x of cosetX(point)) {
			const target = key(x);
			// Scan the run of entries sharing this key.
			for (
				let j = this.#lowerBound(target);
				j < this.#keys.length && this.#keys[j] === target;
				j++
			) {
				const value = BigInt(this.#values[j]);
				if (mulUnsafe(H, value).equals(point)) {
					if (this.#cache.size >= DiscreteLogTable.MAX_CACHE_SIZE) {
						// FIFO eviction: Map iteration is insertion-ordered.
						const oldest = this.#cache.keys().next().value;
						if (oldest !== undefined) this.#cache.delete(oldest);
					}
					this.#cache.set(cacheKey, value);
					return { value, cached: false };
				}
			}
		}
		return undefined;
	}
}

/**
 * Baby-step giant-step search for the `m` with `point = m*H`, over `table`:
 * subtract the giant step each iteration until a baby-step entry matches. Small
 * values (the common case for u16 limbs) are found on the first lookup with no
 * subtraction. Throws {@link DecryptionFailedError} if `m` is outside the table's
 * `2^(2 * numBits)` range.
 */
function solveBsgs(point: RistrettoPoint, table: DiscreteLogTable): bigint {
	const start = performance.now();
	const tableSize = BigInt(table.tableSize);
	for (let g = 0n; g < tableSize; g++) {
		const hit = table.lookup(point);
		if (hit !== undefined) {
			const result = g * tableSize + hit.value;
			if (debugLogging) {
				const elapsed = performance.now() - start;
				console.log(
					`[decrypt] ${hit.cached ? 'cache hit' : 'cache miss'} | ${elapsed.toFixed(1)}ms | value=${result}`,
				);
			}
			return result;
		}
		point = point.subtract(table.giantStep);
	}
	throw new DecryptionFailedError(table.numBits);
}

/**
 * A twisted ElGamal encryption — `ciphertext = r*G + m*H` and
 * `decryptionHandle = r*pk` — of a u16 value (decryptable up to ~2^32).
 *
 * The two fields match the `contra::twisted_elgamal::Encryption` Move
 * struct. Use `Ciphertext.fromBcs` to lift the raw shape produced by the
 * generated `twisted_elgamal.Encryption` BCS schema into a `Ciphertext`.
 */
export class Ciphertext {
	ciphertext: RistrettoPoint;
	decryptionHandle: RistrettoPoint;

	constructor(ciphertext: RistrettoPoint, decryptionHandle: RistrettoPoint) {
		this.ciphertext = ciphertext;
		this.decryptionHandle = decryptionHandle;
	}

	static encryptWithBlinding(
		pk: PublicKey,
		value: bigint,
		blinding: bigint,
	): { ciphertext: Ciphertext; blinding: bigint } {
		const commitment = new PedersenCommitment(value, blinding);
		return { ciphertext: new Ciphertext(commitment.p, mul(pk, blinding)), blinding };
	}

	static encrypt(pk: PublicKey, value: bigint): { ciphertext: Ciphertext; blinding: bigint } {
		const blinding = randomScalar();
		return Ciphertext.encryptWithBlinding(pk, value, blinding);
	}

	/**
	 * Prove that this ciphertext encrypts zero under the given key pair.
	 * Returns a `DdhNizk` proving `decryptionHandle = sk * ciphertext`.
	 */
	proveIsZero(dst: Uint8Array, sk: PrivateKey, pk: PublicKey): DdhNizk {
		return DdhNizk.prove(dst, sk, [G, this.ciphertext], [pk, this.decryptionHandle]);
	}

	/**
	 * Prove that this ciphertext decrypts to `value` under the key pair
	 * `(sk, pk)`, without revealing `sk`.
	 */
	proveDecryption(dst: Uint8Array, sk: PrivateKey, pk: PublicKey, value: bigint): DdhNizk {
		const commitmentToZero = this.ciphertext.subtract(mul(H, value));
		return DdhNizk.prove(dst, sk, [G, commitmentToZero], [pk, this.decryptionHandle]);
	}

	/**
	 * Verify a `proveDecryption` proof: returns `true` iff `proof`
	 * demonstrates that this ciphertext decrypts to `value` under the
	 * secret key corresponding to `pk`.
	 */
	verifyDecryption(dst: Uint8Array, pk: PublicKey, value: bigint, proof: DdhNizk): boolean {
		const commitmentToZero = this.ciphertext.subtract(mul(H, value));
		return proof.verify(dst, [G, commitmentToZero], [pk, this.decryptionHandle]);
	}

	/**
	 * Construct a `Ciphertext` from the BCS-decoded shape produced by the
	 * generated `twisted_elgamal.Encryption` schema.
	 */
	static fromBcs(raw: {
		ciphertext: { bytes: number[] };
		decryption_handle: { bytes: number[] };
	}): Ciphertext {
		return new Ciphertext(pointFromBcs(raw.ciphertext), pointFromBcs(raw.decryption_handle));
	}

	/** Trivial encryption of `value` with zero blinding: `(value*H, identity)`. */
	static trivial(value: bigint): Ciphertext {
		return new Ciphertext(mul(H, value), ZERO);
	}

	/** Component-wise addition of two ciphertexts. */
	add(other: Ciphertext): Ciphertext {
		return new Ciphertext(
			this.ciphertext.add(other.ciphertext),
			this.decryptionHandle.add(other.decryptionHandle),
		);
	}

	/** Component-wise subtraction. */
	subtract(other: Ciphertext): Ciphertext {
		return new Ciphertext(
			this.ciphertext.subtract(other.ciphertext),
			this.decryptionHandle.subtract(other.decryptionHandle),
		);
	}

	/** Scalar-multiply both components by `2^bits`. */
	shiftLeft(bits: number): Ciphertext {
		const factor = 1n << BigInt(bits);
		return new Ciphertext(mul(this.ciphertext, factor), mul(this.decryptionHandle, factor));
	}

	/**
	 * Decrypt this ciphertext under `privateKey`, recovering the
	 * underlying plaintext via baby-step giant-step over `table`.
	 * Throws {@link DecryptionFailedError} if the plaintext is outside
	 * the table's `2^(2 * numBits)` range or the key is wrong.
	 */
	decrypt(privateKey: PrivateKey, table: DiscreteLogTable): bigint {
		return this.decryptWithInverse(ristretto255.Point.Fn.inv(privateKey), table);
	}

	/**
	 * Like {@link decrypt}, but takes a precomputed scalar-field inverse
	 * of the private key so that callers decrypting many ciphertexts
	 * under the same key invert once and reuse the result.
	 */
	decryptWithInverse(privateKeyInverse: bigint, table: DiscreteLogTable): bigint {
		return solveBsgs(
			this.ciphertext.subtract(mul(this.decryptionHandle, privateKeyInverse)),
			table,
		);
	}

	/**
	 * Recover the plaintext from the commitment alone, given the blinding `r`
	 * used to form it.
	 */
	decryptWithBlinding(blinding: bigint, table: DiscreteLogTable): bigint {
		return solveBsgs(this.ciphertext.subtract(mul(G, blinding)), table);
	}
}

/**
 * Four twisted ElGamal ciphertext limbs that together represent an
 * on-chain `contra::encrypted_amount::EncryptedAmount`. The underlying
 * plaintext is `l0 + 2^16 * l1 + 2^32 * l2 + 2^48 * l3`.
 */
export class EncryptedAmount {
	l0: Ciphertext;
	l1: Ciphertext;
	l2: Ciphertext;
	l3: Ciphertext;

	constructor(l0: Ciphertext, l1: Ciphertext, l2: Ciphertext, l3: Ciphertext) {
		this.l0 = l0;
		this.l1 = l1;
		this.l2 = l2;
		this.l3 = l3;
	}

	/**
	 * Construct an `EncryptedAmount` from the BCS-decoded shape produced by the generated
	 * `encrypted_amount.EncryptedAmount` schema.
	 */
	static fromBcs(raw: {
		l0: { ciphertext: { bytes: number[] }; decryption_handle: { bytes: number[] } };
		l1: { ciphertext: { bytes: number[] }; decryption_handle: { bytes: number[] } };
		l2: { ciphertext: { bytes: number[] }; decryption_handle: { bytes: number[] } };
		l3: { ciphertext: { bytes: number[] }; decryption_handle: { bytes: number[] } };
	}): EncryptedAmount {
		return new EncryptedAmount(
			Ciphertext.fromBcs(raw.l0),
			Ciphertext.fromBcs(raw.l1),
			Ciphertext.fromBcs(raw.l2),
			Ciphertext.fromBcs(raw.l3),
		);
	}

	/** Trivially encrypt `value` with zero blinding, splitting it into four u16 limbs. */
	static trivial(value: bigint): EncryptedAmount {
		return new EncryptedAmount(
			Ciphertext.trivial(value & 0xffffn),
			Ciphertext.trivial((value >> 16n) & 0xffffn),
			Ciphertext.trivial((value >> 32n) & 0xffffn),
			Ciphertext.trivial((value >> 48n) & 0xffffn),
		);
	}

	/** The four limbs in order, `[l0, l1, l2, l3]`. */
	get limbs(): [Ciphertext, Ciphertext, Ciphertext, Ciphertext] {
		return [this.l0, this.l1, this.l2, this.l3];
	}

	/**
	 * Combine the four limbs into a single `Ciphertext` encoding the full u64
	 * value, matching the on-chain `encrypted_amount::collapse`.
	 */
	collapse(): Ciphertext {
		return this.l0.add(this.l1.shiftLeft(16).add(this.l2.shiftLeft(32).add(this.l3.shiftLeft(48))));
	}

	/**
	 * Decrypt all four limbs and combine into the underlying u64 plaintext
	 * `l0 + 2^16 * l1 + 2^32 * l2 + 2^48 * l3`.
	 */
	decrypt(privateKey: PrivateKey, table: DiscreteLogTable): bigint {
		const inv = ristretto255.Point.Fn.inv(privateKey);
		return this.limbs.reduce(
			(acc, limb, k) => acc + (limb.decryptWithInverse(inv, table) << BigInt(16 * k)),
			0n,
		);
	}

	/**
	 * Recover the plaintext from the limb commitments alone, given the per-limb
	 * blindings.
	 */
	decryptWithBlindings(
		blindingForLimb: (limbIndex: number) => bigint,
		table: DiscreteLogTable,
	): bigint {
		return this.limbs.reduce(
			(acc, limb, k) => acc + (limb.decryptWithBlinding(blindingForLimb(k), table) << BigInt(16 * k)),
			0n,
		);
	}
}

export function collapseBlindings(blindings: { blinding: bigint }[]): bigint {
	return blindings
		.map((e) => e.blinding)
		.reduce((acc, r, i) => {
			const shift = BigInt(i * 16);
			const shifted = shift === 0n ? r : ristretto255.Point.Fn.create(r * (1n << shift));
			return ristretto255.Point.Fn.create(acc + shifted);
		}, 0n);
}
