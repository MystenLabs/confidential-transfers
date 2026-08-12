// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bcs } from '@mysten/sui/bcs';
import type { Transaction } from '@mysten/sui/transactions';
import {
	deriveDynamicFieldID,
	deriveObjectID,
	normalizeStructTag,
	SUI_FRAMEWORK_ADDRESS,
} from '@mysten/sui/utils';
import { ristretto255 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { hexToBytes } from '@noble/hashes/utils.js';

import type { BatchRangeProver } from './bp.js';
import * as auditorsContracts from './contracts/contra/auditors.js';
import * as decodeContracts from './contracts/contra/decode.js';
import * as encryptedAmountContracts from './contracts/contra/encrypted_amount.js';
import * as twistedElgamalContracts from './contracts/contra/twisted_elgamal.js';
import { InvalidArgumentError } from './error.js';
import type { DdhNizk } from './nizk.js';
import { ElGamalNizk } from './nizk.js';
import { type RistrettoPoint } from './ristretto255.js';
import type { Ciphertext } from './twisted_elgamal.js';
import type { ContraPackageConfig } from './types.js';

/** BCS layout of the Fiat-Shamir transcript: an ordered list of length-prefixed byte chunks. */
const FIAT_SHAMIR_TRANSCRIPT = bcs.vector(bcs.vector(bcs.u8()));

/**
 * Fiat-Shamir challenge over the ordered byte chunks `parts`, matching on-chain
 * `contra::nizk::fiat_shamir_challenge`: BCS-encode `parts` as a `vector<vector<u8>>` (ULEB128
 * chunk count, then each chunk length-prefixed), Blake2b256, then reduce to a scalar by zeroing the
 * top byte (the lower 248 bits are always below the ~2^252 group order).
 */
export function fiatShamirChallenge(randomOracleInputs: Uint8Array[]): bigint {
	const preimage = FIAT_SHAMIR_TRANSCRIPT.serialize(
		randomOracleInputs.map((p) => Array.from(p)),
	).toBytes();
	const hash = blake2b(preimage, { dkLen: 32 });
	hash[31] = 0;
	return ristretto255.Point.Fn.create(bytesToNumberLE(hash));
}

/** Domain-separation byte for DDH proofs in Fiat-Shamir transcripts. */
export const PROTOCOL_DDH = 0x01;
/** Domain-separation byte for ElGamal proofs in Fiat-Shamir transcripts. */
export const PROTOCOL_ELGAMAL = 0x02;
/** Domain-separation byte for 16-bit (amount well-formedness) Bulletproof range proofs. */
export const PROTOCOL_RANGE_PROOF_16 = 0x04;
/** Domain-separation byte for the batched re-keying DDH proof (Π_rekey). */
export const PROTOCOL_BATCH_DDH = 0x06;
/** Domain-separation byte for the batched per-transfer auditor ElGamal proof. */
export const PROTOCOL_AUDITOR_ELGAMAL = 0x07;
/**
 * Domain-separation byte for the client-only verified-decryption DDH proof
 * produced by `TokenAccount.decryptWithProof`.
 */
export const PROTOCOL_VERIFIED_DEC = 100;

/** 20-byte per-account `session_id`: first 20 bytes of {@link getTokenAccountUniqueId}. */
export function newSessionId(
	packageConfig: ContraPackageConfig,
	address: string,
	tokenType: string,
): Uint8Array {
	return hexToBytes(getTokenAccountUniqueId(packageConfig, address, tokenType).slice(2)).subarray(
		0,
		20,
	);
}

/**
 * Deterministic per-`(account, tokenType)` address used only as the Fiat-Shamir
 * session-id tag. It is `derived_object::derive_address(Account UID,
 * TokenAccountKey<tokenType>())`, matching on-chain `contra::session_id`.
 */
export function getTokenAccountUniqueId(
	packageConfig: ContraPackageConfig,
	address: string,
	tokenType: string,
): string {
	const normalizedType = normalizeStructTag(tokenType);
	return deriveObjectID(
		getAccountId(packageConfig, address),
		`${packageConfig.packageId}::contra::TokenAccountKey<${normalizedType}>`,
		bcs.byteVector().serialize([]).toBytes(),
	);
}

/** 21-byte Fiat-Shamir DST `session_id ‖ protocol_id`. */
export function dst(sessionId: Uint8Array, protocolId: number): Uint8Array {
	const result = new Uint8Array(21);
	result.set(sessionId, 0);
	result[20] = protocolId;
	return result;
}

/** A limb of an `EncryptedAmount`: plaintext, blinding, and encryption. */
export type WellFormedLimb = {
	value: bigint;
	blinding: bigint;
	ciphertext: Ciphertext;
};

/** An amount's four limbs plus the public key they're encrypted under. `buildWellFormedProof`
 *  folds each amount's limbs into a single `ElGamalNizk` consistency proof under its `pk`. */
export type WellFormedAmount = {
	limbs: WellFormedLimb[];
	pk: RistrettoPoint;
};

/** Derive the per-owner shared account object ID. */
export function getAccountId(packageConfig: ContraPackageConfig, address: string): string {
	return deriveObjectID(
		packageConfig.accountRegistryId,
		`${packageConfig.packageId}::contra::AccountKey`,
		bcs.Address.serialize(address).toBytes(),
	);
}

/**
 * Derive the dynamic-field object ID of the `TokenAccount<tokenType>` inside
 * the account owned by `address`.
 */
export function getTokenAccountId(
	packageConfig: ContraPackageConfig,
	address: string,
	tokenType: string,
): string {
	const normalizedType = normalizeStructTag(tokenType);
	return deriveDynamicFieldID(
		getAccountId(packageConfig, address),
		`${packageConfig.packageId}::contra::TokenAccountKey<${normalizedType}>`,
		bcs.byteVector().serialize([]).toBytes(),
	);
}

/** Derive the shared `ConfidentialToken<tokenType>` object ID. */
export function getConfidentialTokenId(
	packageConfig: ContraPackageConfig,
	tokenType: string,
): string {
	const normalizedType = normalizeStructTag(tokenType);
	return deriveObjectID(
		packageConfig.tokenRegistryId,
		`${packageConfig.packageId}::contra::TokenKey<${normalizedType}>`,
		bcs.byteVector().serialize([]).toBytes(),
	);
}

/** Serialize a ristretto255 point into an on-chain `Element<G>`. */
export function point(bytes: Uint8Array) {
	return (tx: Transaction) =>
		tx.moveCall({
			target: `${SUI_FRAMEWORK_ADDRESS}::ristretto255::g_from_bytes`,
			arguments: [tx.pure.vector('u8', bytes)],
		});
}

/**
 * Element encodings (points/scalars, 32 bytes each) as the `parts` argument for the generated
 * `contra::decode` constructors, which validate every point via `g_from_bytes` and every scalar via
 * `scalar_from_bytes` — byte-for-byte equivalent to building the value element-by-element, but in a
 * single Move call.
 */
function elemParts(elems: Uint8Array[]): number[][] {
	return elems.map((e) => Array.from(e));
}

/** Serialize `points` into an on-chain `vector<Element<G>>` via `decode::g_vector`. */
export function buildGVector(packageId: string, points: RistrettoPoint[]) {
	return decodeContracts.gVector({
		package: packageId,
		arguments: { parts: elemParts(points.map((p) => p.toBytes())) },
	});
}

/**
 * Build an on-chain `vector<twisted_elgamal::PublicKey>` from ristretto points in a single
 * `decode::public_keys` call (each point is validated non-identity by `public_key`). Used for
 * `batched_transfer`'s receiver keys and the `update_auditors` / `new_confidential_token` auditor
 * keys — the elements need a nested `public_key(g_from_bytes(..))`, so a `makeMoveVec` of per-element
 * calls does not round-trip; the single decode call does.
 */
export function buildPublicKeyVector(packageId: string, points: RistrettoPoint[]) {
	return decodeContracts.publicKeys({
		package: packageId,
		arguments: { parts: elemParts(points.map((p) => p.toBytes())) },
	});
}

/** Serialize a `Ciphertext` into an on-chain `Encryption`. */
export function buildEncryption(packageId: string, ct: Ciphertext) {
	return decodeContracts.encryption({
		package: packageId,
		arguments: { parts: elemParts([ct.ciphertext.toBytes(), ct.decryptionHandle.toBytes()]) },
	});
}

/**
 * Serialize a `DdhNizk` into an on-chain `DdhProof`. The byte layout is the per-pair Schnorr
 * commitments followed by the trailing scalar response `z`, matching `decode::ddh_proof`.
 */
export function buildDdhProof(packageId: string, proof: DdhNizk) {
	return decodeContracts.ddhProof({
		package: packageId,
		arguments: {
			parts: elemParts([
				...proof.commitments.map((c) => c.toBytes()),
				numberToBytesLE(proof.z, 32),
			]),
		},
	});
}

/**
 * Serialize a vector of equal-length `DdhNizk`s into an on-chain `vector<DdhProof>` via
 * `decode::ddh_proofs`: each proof's commitments (all `numCommitments` of them) followed by its scalar
 * `z`, concatenated. Every proof must have the same commitment count (here `1 + auditor count`).
 */
export function buildDdhProofs(packageId: string, proofs: DdhNizk[]) {
	const numCommitments = proofs.length > 0 ? proofs[0].commitments.length : 0;
	return decodeContracts.ddhProofs({
		package: packageId,
		arguments: {
			parts: elemParts(
				proofs.flatMap((p) => [...p.commitments.map((c) => c.toBytes()), numberToBytesLE(p.z, 32)]),
			),
			numCommitments,
		},
	});
}

/** Serialize an `ElGamalNizk` consistency proof into an on-chain `ElGamalProof`. */
export function buildElGamalProof(packageId: string, proof: ElGamalNizk) {
	return decodeContracts.elgamalProof({
		package: packageId,
		arguments: {
			parts: elemParts([
				proof.a.toBytes(),
				proof.b.toBytes(),
				numberToBytesLE(proof.z1, 32),
				numberToBytesLE(proof.z2, 32),
			]),
		},
	});
}

/**
 * Serialize a Move call sequence that constructs a raw `EncryptedAmount`
 * on chain from four ciphertext limbs (no range or consistency proof).
 */
export function buildEncryptedAmount(packageId: string, limbs: Ciphertext[]) {
	if (limbs.length !== 4) {
		throw new InvalidArgumentError(
			`buildEncryptedAmount requires exactly 4 limbs, got ${limbs.length}`,
		);
	}
	return decodeContracts.encryptedAmount({
		package: packageId,
		arguments: {
			parts: elemParts(
				limbs.flatMap((l) => [l.ciphertext.toBytes(), l.decryptionHandle.toBytes()]),
			),
		},
	});
}

/**
 * Maximum number of amounts a single Bulletproof chunk can cover. Sui's
 * `rangeproofs::verify_bulletproofs_with_dst_ristretto255` caps the aggregated commitment count at 32 for
 * 16-bit range proofs, and each amount contributes 4 limb commitments, so a chunk holds at most
 * `32 / 4 = 8` amounts. Mirrors `MAX_BATCH_SIZE` in `encrypted_amount.move`.
 */
const MAX_BATCH_SIZE = 8;

/**
 * Build a `WellFormedProof` covering a batch of `EncryptedAmount`s on chain via
 * `encrypted_amount::new_well_formed_proof`. Sui's bulletproof aggregator requires the number of
 * committed values to be a power of 2 and at most `MAX_BATCH_SIZE` amounts (= 32 commitments) per
 * proof; we partition N amounts into power-of-2 chunks largest-first, capped at `MAX_BATCH_SIZE`
 * (e.g. N=7 → [4, 2, 1]; N=20 → [8, 8, 4]). The on-chain verifier reconstructs the same partition
 * from N, so no explicit sizes vector needs to be carried. Each amount's four limbs are folded
 * into a single `ElGamalNizk` consistency proof under that amount's `pk` and the `elgamalDst` tag
 * (the `DST_ELGAMAL` the Move entry passes to `encrypted_amount::verify`). The pk isn't stored in
 * the proof; the consumer supplies a parallel `vector<Element<G>>` to `verify`, so callers must
 * hand pks separately to whichever Move entry verifies the proof. `rangeDst` is the
 * domain-separation tag bound into the Bulletproof transcript; it must equal the entry's
 * `range_dst` (the `DST_RANGE_PROOF` tag) — distinct from `elgamalDst` so a range proof can't be
 * replayed as a consistency proof.
 */
export function buildWellFormedProof(
	batchRangeProver: BatchRangeProver,
	rangeDst: Uint8Array,
	elgamalDst: Uint8Array,
	packageId: string,
	batch: WellFormedAmount[],
) {
	// Greedily take as many MAX_BATCH_SIZE chunks as fit, then halve the chunk size and repeat
	// until the batch is exhausted — the same canonical partition `batch_sizes` reconstructs on
	// chain. The Pedersen commitments produced by `batchRangeProver` (the caller's bound function
	// from `getBulletproofs()`) equal the ciphertexts' first components (same H, G, blinding), so
	// no separate commitment argument is needed.
	const rangeProofs: number[][] = [];
	let offset = 0;
	let remaining = batch.length;
	let chunkSize = MAX_BATCH_SIZE;
	while (remaining > 0) {
		while (remaining >= chunkSize) {
			const chunk = batch.slice(offset, offset + chunkSize);
			rangeProofs.push(
				Array.from(
					batchRangeProver(
						chunk.flatMap((amount) => amount.limbs.map((l) => l.value)),
						chunk.flatMap((amount) => amount.limbs.map((l) => l.blinding)),
						16,
						rangeDst,
					).proof,
				),
			);
			offset += chunkSize;
			remaining -= chunkSize;
		}
		chunkSize = Math.floor(chunkSize / 2);
	}
	// One witness-folded `ElGamalNizk` per amount, covering its four same-key limbs.
	const consistencyProofs = batch.map((amount) =>
		ElGamalNizk.prove(elgamalDst, amount.pk, amount.limbs),
	);
	return (tx: Transaction) =>
		encryptedAmountContracts.newWellFormedProof({
			package: packageId,
			arguments: {
				rangeProofs,
				consistencyProofs: tx.makeMoveVec({
					type: `${packageId}::nizk::ElGamalProof`,
					elements: consistencyProofs.map((proof) =>
						decodeContracts.elgamalProof({
							package: packageId,
							arguments: {
								parts: elemParts([
									proof.a.toBytes(),
									proof.b.toBytes(),
									numberToBytesLE(proof.z1, 32),
									numberToBytesLE(proof.z2, 32),
								]),
							},
						})(tx),
					),
				}),
			},
		})(tx);
}

/**
 * Single-amount convenience: build an on-chain `EncryptedAmount` paired with a batch-of-1
 * `WellFormedProof` over those four limbs. Returns the two `TransactionResult`s so callers can
 * pass them as adjacent arguments to a consumer that takes `(EncryptedAmount, WellFormedProof)` —
 * `unwrap`, `update_active_balance`, `set_public_key`, or the sender's new-balance slot of
 * `batched_transfer`. Takes `tx` directly rather than returning a `(tx) => ...` thunk because
 * `tx.add` only accepts thunks that return a single `TransactionResult`.
 */
export function buildEncryptedAmountAndProof(
	batchRangeProver: BatchRangeProver,
	rangeDst: Uint8Array,
	elgamalDst: Uint8Array,
	tx: Transaction,
	packageId: string,
	amount: WellFormedAmount,
) {
	return {
		encryptedAmount: tx.add(
			buildEncryptedAmount(
				packageId,
				amount.limbs.map((l) => l.ciphertext),
			),
		),
		wellFormedProof: tx.add(
			buildWellFormedProof(batchRangeProver, rangeDst, elgamalDst, packageId, [amount]),
		),
	};
}

/**
 * Wrap a ristretto255 point into an on-chain `twisted_elgamal::PublicKey` via `public_key`, which
 * asserts the point is non-identity. Every contra entry that keys a balance or installs an auditor
 * key takes a `PublicKey`, so callers build one through this helper.
 */
export function buildPublicKey(packageId: string, pk: RistrettoPoint) {
	return twistedElgamalContracts.publicKey({
		package: packageId,
		arguments: { element: point(pk.toBytes()) },
	});
}

/**
 * Build an `Option<twisted_elgamal::PublicKey>` for an optional public key (e.g. the account's
 * optional default key passed to `set_default_pk_as_sender`, or an auditor key passed to
 * `update_auditor` / `new_confidential_token`). `option::some(public_key(pk))` when a point is
 * given, `option::none` otherwise.
 */
export function buildOptionalPublicKey(packageId: string, pk?: RistrettoPoint) {
	const optionType = [`${packageId}::twisted_elgamal::PublicKey`];
	if (pk) {
		return (tx: Transaction) =>
			tx.moveCall({
				target: '0x1::option::some',
				typeArguments: optionType,
				arguments: [buildPublicKey(packageId, pk)],
			});
	}
	return (tx: Transaction) =>
		tx.moveCall({ target: '0x1::option::none', typeArguments: optionType });
}

/**
 * Build an `Option<auditors::AuditorPackage>` — the per-transfer auditor data: the auditor's two
 * u32-limb decryption handles per receiver plus one batched `DdhProof` per receiver. `option::some`
 * wrapping `auditors::new_auditor_package(handles, proofs)` when `data` is provided, `option::none`
 * when auditing is disabled. `data.handles` are flattened in receiver order (two per receiver),
 * grouped into per-receiver `[lo, hi]` handle vectors on-chain by `decode::decryption_handles`. Built
 * entirely through `decode` calls (no `makeMoveVec`), so the nested proof/handle structure round-trips
 * on chain.
 */
export function buildAuditorPackageOption(
	packageId: string,
	data?: { handles: RistrettoPoint[]; proofs: DdhNizk[] },
) {
	const optionType = [`${packageId}::auditors::AuditorPackage`];
	if (data) {
		return (tx: Transaction) =>
			tx.moveCall({
				target: '0x1::option::some',
				typeArguments: optionType,
				arguments: [
					auditorsContracts.newAuditorPackage({
						package: packageId,
						arguments: {
							handles: decodeContracts.decryptionHandles({
								package: packageId,
								arguments: { parts: elemParts(data.handles.map((h) => h.toBytes())) },
							}),
							proofs: buildDdhProofs(packageId, data.proofs),
						},
					}),
				],
			});
	}
	return (tx: Transaction) =>
		tx.moveCall({ target: '0x1::option::none', typeArguments: optionType });
}
