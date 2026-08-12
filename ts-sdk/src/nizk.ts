// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ristretto255 } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';

import { fiatShamirChallenge } from './helpers.js';
import { G, H, mul, randomScalar, ZERO, type RistrettoPoint } from './ristretto255.js';
import type { Ciphertext } from './twisted_elgamal.js';

// ---------------------------------------------------------------------------
// DDH NIZK — matches Move's `contra::nizk::DdhProof`
// ---------------------------------------------------------------------------

/**
 * Fiat-Shamir challenge for the DDH proof. Binds, in order, the DST, every base, every
 * image, and every per-pair Schnorr commitment (matching Move's `challenge_ddh`).
 * Exported for the transcript-regression test only — not part of the public API.
 */
export function challengeDdh(
	dst: Uint8Array,
	bases: RistrettoPoint[],
	images: RistrettoPoint[],
	commitments: RistrettoPoint[],
): bigint {
	return fiatShamirChallenge([
		dst,
		...bases.map((b) => b.toBytes()),
		...images.map((i) => i.toBytes()),
		...commitments.map((c) => c.toBytes()),
	]);
}

/**
 * Fiat-Shamir challenge for a batched DDH proof (`DdhNizk.proveBatch`). Binds, in order, the DST,
 * every base, then every witness's images witness-major (all of witness 0, then witness 1, …), then
 * every Schnorr commitment (matching Move's `challenge_ddh_batch`).
 * Exported for the transcript-regression test only — not part of the public API.
 */
export function challengeDdhBatch(
	dst: Uint8Array,
	bases: RistrettoPoint[],
	imagesPerWitness: RistrettoPoint[][],
	commitments: RistrettoPoint[],
): bigint {
	return fiatShamirChallenge([
		dst,
		...bases.map((b) => b.toBytes()),
		...imagesPerWitness.flatMap((images) => images.map((i) => i.toBytes())),
		...commitments.map((c) => c.toBytes()),
	]);
}

/**
 * Non-interactive zero-knowledge proof of a shared-witness DDH relation over a batch of base/image
 * pairs: proves knowledge of a single `w` such that `images[k] = w * bases[k]` for every `k`.
 *
 * Layout matches the on-chain `contra::nizk::DdhProof` struct.
 */
export class DdhNizk {
	commitments: RistrettoPoint[];
	z: bigint;

	constructor(commitments: RistrettoPoint[], z: bigint) {
		this.commitments = commitments;
		this.z = z;
	}

	static prove(
		dst: Uint8Array,
		w: bigint,
		bases: RistrettoPoint[],
		images: RistrettoPoint[],
	): DdhNizk {
		const s = randomScalar();
		const commitments = bases.map((b) => mul(b, s));
		const c = challengeDdh(dst, bases, images, commitments);
		const z = ristretto255.Point.Fn.create(s + c * w);
		return new DdhNizk(commitments, z);
	}

	/**
	 * Batch several DDH relations that share one base set but have independent witnesses into a single
	 * proof: `witnesses[l]` opens `imagesPerWitness[l][k] = witnesses[l] * bases[k]` for every `k`. The
	 * per-witness image vectors are folded into each base's Schnorr row with powers of the challenge
	 * (`c^{l+1}`), so the proof stays `bases.length` commitments + `1` response regardless of the
	 * witness count. Verified on-chain by `nizk::verify_ddh_batch`.
	 */
	static proveBatch(
		dst: Uint8Array,
		witnesses: bigint[],
		bases: RistrettoPoint[],
		imagesPerWitness: RistrettoPoint[][],
	): DdhNizk {
		const s = randomScalar();
		const commitments = bases.map((b) => mul(b, s));
		const c = challengeDdhBatch(dst, bases, imagesPerWitness, commitments);
		// z = s + sum_l c^{l+1} w_l.
		let z = s;
		let power = c;
		for (const w of witnesses) {
			z = ristretto255.Point.Fn.create(z + power * w);
			power = ristretto255.Point.Fn.create(power * c);
		}
		return new DdhNizk(commitments, z);
	}

	verify(dst: Uint8Array, bases: RistrettoPoint[], images: RistrettoPoint[]): boolean {
		if (images.length !== bases.length || this.commitments.length !== bases.length) return false;
		const c = challengeDdh(dst, bases, images, this.commitments);
		// z * bases[k] == commitments[k] + c * images[k]
		return bases.every((base, k) =>
			isValidRelation(this.commitments[k], images[k], base, this.z, c),
		);
	}

	/** Verify a proof from {@link proveBatch}; mirrors Move's `nizk::verify_ddh_batch`. */
	verifyBatch(
		dst: Uint8Array,
		bases: RistrettoPoint[],
		imagesPerWitness: RistrettoPoint[][],
	): boolean {
		if (this.commitments.length !== bases.length) return false;
		if (imagesPerWitness.some((images) => images.length !== bases.length)) return false;
		const c = challengeDdhBatch(dst, bases, imagesPerWitness, this.commitments);
		// Fold each base's images with powers of `c` (c^0, c^1, …); isValidRelation's own `c` factor
		// then weights witness `l` by `c^{l+1}`: commitments[k] + c * folded == z * bases[k].
		return bases.every((base, k) => {
			let folded = ZERO;
			let power = 1n;
			for (const images of imagesPerWitness) {
				folded = folded.add(mul(images[k], power));
				power = ristretto255.Point.Fn.create(power * c);
			}
			return isValidRelation(this.commitments[k], folded, base, this.z, c);
		});
	}
}

function isValidRelation(
	e1: RistrettoPoint,
	e2: RistrettoPoint,
	e3: RistrettoPoint,
	z: bigint,
	c: bigint,
): boolean {
	return equalBytes(e1.toBytes(), mul(e3, z).subtract(mul(e2, c)).toBytes());
}

// ---------------------------------------------------------------------------
// ElGamal NIZK — matches Move's `contra::nizk::ElGamalProof`
// ---------------------------------------------------------------------------

/** A ciphertext together with its opening — one instance of the batched ElGamal relation. */
export type ElGamalInstance = {
	ciphertext: Ciphertext;
	value: bigint;
	blinding: bigint;
};

/**
 * Fiat-Shamir challenge for the ElGamal proof. Binds, in order, the DST, the bases `g, h`, the
 * shared public key, every ciphertext `(C_j, D_j)`, and the two mask commitments `(a, b)`
 * (matching Move's `challenge_elgamal`).
 * Exported for the transcript-regression test only — not part of the public API.
 */
export function challengeElgamal(
	dst: Uint8Array,
	pk: RistrettoPoint,
	encryptions: Ciphertext[],
	a: RistrettoPoint,
	b: RistrettoPoint,
): bigint {
	return fiatShamirChallenge([
		dst,
		G.toBytes(),
		H.toBytes(),
		pk.toBytes(),
		...encryptions.flatMap((e) => [e.ciphertext.toBytes(), e.decryptionHandle.toBytes()]),
		a.toBytes(),
		b.toBytes(),
	]);
}

/**
 * Non-interactive zero-knowledge proof that a batch of twisted ElGamal ciphertexts sharing one
 * public key `pk` are all well-formed: proves knowledge of `(r_j, m_j)` with `C_j = r_j*G + m_j*H`
 * and `D_j = r_j*pk` for every `j`.
 *
 * Layout matches the on-chain `contra::nizk::ElGamalProof` struct.
 */
export class ElGamalNizk {
	a: RistrettoPoint;
	b: RistrettoPoint;
	z1: bigint;
	z2: bigint;

	constructor(a: RistrettoPoint, b: RistrettoPoint, z1: bigint, z2: bigint) {
		this.a = a;
		this.b = b;
		this.z1 = z1;
		this.z2 = z2;
	}

	/**
	 * Prove that every entry's `ciphertext` is a valid twisted ElGamal encryption of its `value`
	 * under the shared `pk` with its `blinding`. The bases `g, h` are the canonical Twisted ElGamal
	 * generators — fixed by the protocol, not a parameter.
	 */
	static prove(dst: Uint8Array, pk: RistrettoPoint, entries: ElGamalInstance[]): ElGamalNizk {
		const ma = randomScalar();
		const mb = randomScalar();
		// a = ma*pk (handle side); b = ma*G + mb*H (ciphertext side).
		const a = mul(pk, ma);
		const b = mul(G, ma).add(mul(H, mb));
		const c = challengeElgamal(
			dst,
			pk,
			entries.map((e) => e.ciphertext),
			a,
			b,
		);
		// z1 = ma + sum_j c^j r_j ; z2 = mb + sum_j c^j m_j, with c^j starting at c^1.
		let z1 = ma;
		let z2 = mb;
		let power = c;
		for (const e of entries) {
			z1 = ristretto255.Point.Fn.create(z1 + power * e.blinding);
			z2 = ristretto255.Point.Fn.create(z2 + power * e.value);
			power = ristretto255.Point.Fn.create(power * c);
		}
		return new ElGamalNizk(a, b, z1, z2);
	}
}
