// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ristretto255 } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';

import { fiatShamirChallenge } from './helpers.js';
import { G, H, mul, randomScalar, type RistrettoPoint } from './ristretto255.js';
import type { Ciphertext, MultiRecipientEncryption } from './twisted_elgamal.js';

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

	verify(dst: Uint8Array, bases: RistrettoPoint[], images: RistrettoPoint[]): boolean {
		if (images.length !== bases.length || this.commitments.length !== bases.length) return false;
		const c = challengeDdh(dst, bases, images, this.commitments);
		// z * bases[k] == commitments[k] + c * images[k]
		return bases.every((base, k) =>
			isValidRelation(this.commitments[k], images[k], base, this.z, c),
		);
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

// ---------------------------------------------------------------------------
// Key consistency NIZK — matches Move's `contra::nizk::KeyConsistencyProof`
// ---------------------------------------------------------------------------

/**
 * Split a 256-bit scalar into eight u32 limbs in little-endian order,
 * matching Move's `nizk::scalar_to_limbs`.
 */
export function scalarToLimbs(scalar: bigint): bigint[] {
	return Array.from({ length: 8 }, (_, i) => (scalar >> BigInt(i * 32)) & 0xffffffffn);
}

/**
 * Reassemble eight u32 limbs (little-endian) into a 256-bit scalar.
 * Inverse of `scalarToLimbs`.
 */
export function limbsToScalar(limbs: bigint[]): bigint {
	return limbs.reduce((acc, limb, i) => acc | (limb << BigInt(i * 32)), 0n);
}

/**
 * Fiat-Shamir challenge for the key-consistency proof. Binds the bases `g, h`, the sender public
 * key, the recipient public keys, every per-limb ciphertext with its decryption handles, and
 * finally the prover commitments `(a1, a2, a3)` — matching Move's `challenge_key_consistency`.
 */
function challengeKeyConsistency(
	dst: Uint8Array,
	g: RistrettoPoint,
	h: RistrettoPoint,
	senderPublicKey: RistrettoPoint,
	recipientEncryptionKeys: RistrettoPoint[],
	ciphertexts: MultiRecipientEncryption[],
	a1: RistrettoPoint[],
	a2: RistrettoPoint[],
	a3: RistrettoPoint,
): bigint {
	const randomOracleInputs: Uint8Array[] = [
		dst,
		g.toBytes(),
		h.toBytes(),
		senderPublicKey.toBytes(),
		...recipientEncryptionKeys.map((k) => k.toBytes()),
		...ciphertexts.flatMap((ct) => [
			ct.commitment.toBytes(),
			...ct.decryptionHandles.map((dh) => dh.toBytes()),
		]),
		...a1.map((p) => p.toBytes()),
		...a2.map((p) => p.toBytes()),
		a3.toBytes(),
	];
	return fiatShamirChallenge(randomOracleInputs);
}

/**
 * Non-interactive zero-knowledge proof showing that the eight 32-bit limbs of a 256-bit
 * sender private key are correctly encrypted to a list of recipient public keys using
 * Twisted ElGamal.
 *
 * Proves knowledge of blindings (r_1,...,r_8) and key limbs (u_1,...,u_8) such that:
 *   - D_ij = r_i * pk_j  for all limbs i and recipients j
 *   - C_i  = r_i * G + u_i * H  for all i
 *   - (\sum_i u_i * 2^{32i}) * G == sender_public_key
 *
 * Layout matches the on-chain `contra::nizk::KeyConsistencyProof` struct.
 */
export class KeyConsistencyProof {
	a1: RistrettoPoint[]; // 8*m points: a_i * pk_j, ordered by limb i then recipient j.
	a2: RistrettoPoint[]; // 8 points: a_i * G + b_i * H.
	// Single aggregate mask (\sum_i b_i * 2^{32i}) * G.
	a3: RistrettoPoint;
	z1: bigint[]; // 8 scalars: a_i + c * r_i.
	z2: bigint[]; // 8 scalars: b_i + c * u_i.

	constructor(
		a1: RistrettoPoint[],
		a2: RistrettoPoint[],
		a3: RistrettoPoint,
		z1: bigint[],
		z2: bigint[],
	) {
		this.a1 = a1;
		this.a2 = a2;
		this.a3 = a3;
		this.z1 = z1;
		this.z2 = z2;
	}

	/**
	 * Prove that `ciphertexts` correctly encrypts the 32-bit limbs of the sender's private key
	 * to all `recipientEncryptionKeys`.
	 */
	static prove(
		dst: Uint8Array,
		senderPrivateKeyLimbs: bigint[],
		senderPublicKey: RistrettoPoint,
		recipientEncryptionKeys: RistrettoPoint[],
		ciphertexts: MultiRecipientEncryption[],
		blindings: bigint[],
	): KeyConsistencyProof {
		const n = senderPrivateKeyLimbs.length;

		const a = Array.from({ length: n }, () => randomScalar());
		const b = Array.from({ length: n }, () => randomScalar());

		// a1[i*m + j] = a_i * pk_j
		const a1: RistrettoPoint[] = a.flatMap((ai) =>
			recipientEncryptionKeys.map((pk) => mul(pk, ai)),
		);

		// a2[i] = a_i * G + b_i * H
		const a2: RistrettoPoint[] = Array.from({ length: n }, (_, i) =>
			mul(G, a[i]).add(mul(H, b[i])),
		);

		// a3 = (\sum_i b_i * 2^{32i}) * G
		const bSum = b.reduce(
			(acc, bi, i) => ristretto255.Point.Fn.create(acc + (bi << BigInt(i * 32))),
			0n,
		);
		const a3: RistrettoPoint = mul(G, bSum);

		const c = challengeKeyConsistency(
			dst,
			G,
			H,
			senderPublicKey,
			recipientEncryptionKeys,
			ciphertexts,
			a1,
			a2,
			a3,
		);

		// z1[i] = a_i + c * r_i
		const z1 = a.map((ai, i) => ristretto255.Point.Fn.create(ai + c * blindings[i]));

		// z2[i] = b_i + c * u_i
		const z2 = b.map((bi, i) => ristretto255.Point.Fn.create(bi + c * senderPrivateKeyLimbs[i]));

		return new KeyConsistencyProof(a1, a2, a3, z1, z2);
	}

	/**
	 * Verify the proof against the sender's public key, the recipient encryption keys,
	 * and the per-limb ciphertexts.
	 */
	verify(
		dst: Uint8Array,
		senderPublicKey: RistrettoPoint,
		recipientEncryptionKeys: RistrettoPoint[],
		ciphertexts: MultiRecipientEncryption[],
	): boolean {
		const n = this.a2.length;
		const m = recipientEncryptionKeys.length;

		const c = challengeKeyConsistency(
			dst,
			G,
			H,
			senderPublicKey,
			recipientEncryptionKeys,
			ciphertexts,
			this.a1,
			this.a2,
			this.a3,
		);

		// Check 1: a1[i*m+j] + c * D_ij == z1_i * pk_j  for all (i, j)
		for (let i = 0; i < n; i++) {
			for (let j = 0; j < m; j++) {
				const lhs = this.a1[i * m + j].add(mul(ciphertexts[i].decryptionHandles[j], c));
				const rhs = mul(recipientEncryptionKeys[j], this.z1[i]);
				if (!lhs.equals(rhs)) return false;
			}
		}

		// Check 2: a2_i + c * C_i == z1_i * G + z2_i * H  for all i
		for (let i = 0; i < n; i++) {
			const lhs = this.a2[i].add(mul(ciphertexts[i].commitment, c));
			const rhs = mul(G, this.z1[i]).add(mul(H, this.z2[i]));
			if (!lhs.equals(rhs)) return false;
		}

		// Check 3: (\sum_i z2_i * 2^{32i}) * G == a3 + c * sender_public_key
		const base = 1n << 32n;
		let exp = 1n;
		let zSum = 0n;
		for (let i = 0; i < n; i++) {
			zSum = ristretto255.Point.Fn.create(zSum + this.z2[i] * exp);
			exp = ristretto255.Point.Fn.create(exp * base);
		}
		const lhs3 = mul(G, zSum);
		const rhs3 = this.a3.add(mul(senderPublicKey, c));
		return lhs3.equals(rhs3);
	}
}
