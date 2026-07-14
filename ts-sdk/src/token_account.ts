// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { dst, newSessionId, PROTOCOL_VERIFIED_DEC } from './helpers.js';
import type { DdhNizk } from './nizk.js';
import { assertNonZeroScalar, G, mul, randomScalar, type RistrettoPoint } from './ristretto255.js';
import { recoverTransferRandomness } from './transfer_randomness.js';
import type {
	Ciphertext,
	DiscreteLogTable,
	EncryptedAmount,
	PrivateKey,
	PublicKey,
} from './twisted_elgamal.js';
import type { ContraPackageConfig } from './types.js';

/**
 * Represents a per-(address, tokenType) token account on the client
 * side. Holds the owner's address, the token type, the deployment
 * package config, and the twisted ElGamal private key used for
 * on-chain encryption/decryption.
 *
 * The public key is derived on the fly as `G * privateKey` when
 * needed, so only the scalar private key is stored.
 *
 * If no `privateKey` is supplied at construction time, a fresh one is
 * generated automatically.
 */
export class TokenAccount {
	readonly address: string;
	readonly tokenType: string;
	readonly privateKey: PrivateKey;
	// Will be static per network in the future.
	readonly #packageConfig: ContraPackageConfig;

	constructor(
		address: string,
		tokenType: string,
		packageConfig: ContraPackageConfig,
		privateKey?: PrivateKey,
	) {
		this.address = address;
		this.tokenType = tokenType;
		this.#packageConfig = packageConfig;
		if (privateKey !== undefined) assertNonZeroScalar(privateKey);
		this.privateKey = privateKey ?? randomScalar();
	}

	/** Derive the public key as `G * privateKey`. */
	get publicKey(): PublicKey {
		return mul(G, this.privateKey);
	}

	/**
	 * 21-byte Fiat-Shamir domain-separation tag (DST) for `protocolId` on this
	 * (address, tokenType) account: `TokenAccount<tokenType>.id.bytes[..20] ‖ protocolId`.
	 */
	dst(protocolId: number): Uint8Array {
		return dst(newSessionId(this.#packageConfig, this.address, this.tokenType), protocolId);
	}

	/**
	 * Decrypt an `EncryptedAmount` using this account's private key,
	 * returning the underlying u64 plaintext as a `bigint`.
	 *
	 * Convenience wrapper over `EncryptedAmount.decrypt(privateKey, table)`.
	 */
	decryptAmount(encryptedAmount: EncryptedAmount, table: DiscreteLogTable): bigint {
		return encryptedAmount.decrypt(this.privateKey, table);
	}

	/**
	 * Decrypt a single `Ciphertext` and produce a zero-knowledge proof
	 * that the returned `value` is its plaintext under this account's
	 * key pair.
	 *
	 * The verifier reconstructs the DST as
	 * `verifiedDecDst = dst(newSessionId(packageConfig, address, tokenType), PROTOCOL_VERIFIED_DEC)`
	 * and checks the proof with
	 * `ciphertext.verifyDecryption(verifiedDecDst, publicKey, value, proof)`.
	 */
	decryptWithProof(
		ciphertext: Ciphertext,
		table: DiscreteLogTable,
	): { value: bigint; proof: DdhNizk } {
		const value = ciphertext.decrypt(this.privateKey, table);
		const verifiedDecDst = this.dst(PROTOCOL_VERIFIED_DEC);
		const proof = ciphertext.proveDecryption(
			verifiedDecDst,
			this.privateKey,
			this.publicKey,
			value,
		);
		return { value, proof };
	}

	/**
	 * Recover an outgoing batched-transfer amount this account sent, from the
	 * on-chain `TransferEvent`, without any sender-keyed decryption handle.
	 */
	recoverSentAmount(
		encryptedAmount: EncryptedAmount,
		seedPoint: RistrettoPoint,
		batchIndex: number,
		table: DiscreteLogTable,
	): bigint {
		const randomness = recoverTransferRandomness(this.privateKey, seedPoint);
		return encryptedAmount.decryptWithBlindings(
			(limbIndex) => randomness.blinding(batchIndex, limbIndex),
			table,
		);
	}
}
