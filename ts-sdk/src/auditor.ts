// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import * as contraContracts from './contracts/contra/contra.js';
import { Field as DynamicField } from './contracts/sui/dynamic_field.js';
import { InvalidArgumentError } from './error.js';
import { getTokenAccountId } from './helpers.js';
import { limbsToScalar } from './nizk.js';
import { G, mul, pointFromBcs, GROUP_ORDER } from './ristretto255.js';
import { TokenAccount } from './token_account.js';
import {
	MultiRecipientEncryption,
	type DiscreteLogTable,
	type PrivateKey,
	type PublicKey,
} from './twisted_elgamal.js';
import type {
	AuditorVersionEntry,
	ContraAuditorOptions,
	ContraCompatibleClient,
	ContraPackageConfig,
	VerifiedKeyEncryption,
} from './types.js';

/**
 * Auditor SDK. Recovers a user's private key from the on-chain `verified_key_encryption` field
 * of their `TokenAccount<T>`, returning a fully-keyed `TokenAccount` that
 * can decrypt the user's balances and any event amounts encrypted to them.
 *
 * A set of auditor keys is versioned. The auditor needs to know one secret key for each version
 * in order to decrypt all accounts.
 *
 * Previously registered user private keys can be recovered from NewRegistrationEvent and
 * UpdatedPublicKeyEvent events.
 */
export class ContraAuditor {
	#suiClient: ContraCompatibleClient;
	#packageConfig: ContraPackageConfig; // Will be static per network in the future.
	#tokenType: string;
	#table: DiscreteLogTable;
	#auditorKeyForVersion: Map<number, AuditorVersionEntry>;

	constructor(options: ContraAuditorOptions) {
		this.#suiClient = options.suiClient;
		this.#packageConfig = options.packageConfig;
		this.#tokenType = options.tokenType;
		this.#table = options.table;
		this.#auditorKeyForVersion = options.auditorKeyForVersion;
	}

	get tokenType(): string {
		return this.#tokenType;
	}

	/**
	 * Decrypt the user's private key from a parsed `VerifiedKeyEncryption`.
	 *
	 * The input shape — `{ ciphertext: MultiRecipientEncryption[]; version: number }` —
	 * matches the `verified_key_encryption` field on `TokenAccount<T>` (the current state)
	 * **and** on `NewRegistrationEvent<T>` and `UpdatedPublicKeyEvent<T>`. Pass an event's
	 * `verified_key_encryption` here to recover the user's private key as of the version
	 * that was active at registration / key-rotation time — useful when tracking historical
	 * state across `set_public_key` calls.
	 *
	 * `expectedPk` should be the account/event public key from the same object or event.
	 *
	 * @throws if `ciphertext` is empty (the user registered when no auditors were configured),
	 * if this auditor has no record for `version`, if the recorded `index` is out of range for any per-limb
	 * ciphertext, or if the recovered key does not match `expectedPk`.
	 */
	recoverPrivateKey(
		{ ciphertext, version }: VerifiedKeyEncryption,
		expectedPk: PublicKey,
	): PrivateKey {
		if (ciphertext.length === 0) {
			throw new InvalidArgumentError(
				`Cannot recover private key: account was registered with no auditors (version ${version}).`,
			);
		}
		const entry = this.#auditorKeyForVersion.get(version);
		if (entry === undefined) {
			const known = Array.from(this.#auditorKeyForVersion.keys())
				.sort((a, b) => a - b)
				.join(', ');
			throw new InvalidArgumentError(
				`Auditor has no record for version ${version}. Known versions: [${known}].`,
			);
		}
		const limbs = ciphertext.map((mrc, i) => {
			if (entry.index >= mrc.decryptionHandles.length) {
				throw new InvalidArgumentError(
					`Auditor index ${entry.index} out of range for limb ${i} (have ${mrc.decryptionHandles.length} recipients) at version ${version}.`,
				);
			}
			return mrc.decrypt(entry.index, entry.privateKey, this.#table);
		});
		// The on-chain key-consistency proof only binds the reconstructed limbs to the account
		// public key modulo the group order, so reduce to the canonical representation.
		// TODO: Maybe log when a recovered key is not canonical?
		const recoveredKey = limbsToScalar(limbs) % GROUP_ORDER;

		if (!mul(G, recoveredKey).equals(expectedPk)) {
			throw new InvalidArgumentError(
				`Recovered key does not match the account public key (version ${version}); ` +
					`the key-encryption payload is forged or corrupted.`,
			);
		}
		return recoveredKey;
	}

	/**
	 * Fetch the on-chain `TokenAccount<tokenType>` belonging to `address`, decrypt the user's
	 * private key from `verified_key_encryption`, and return a fully-keyed `TokenAccount`.
	 *
	 * The returned `TokenAccount` can be used with `ContraClient.getBalance` to read the user's
	 * balance, or with `TokenAccount.decryptAmount` / `EncryptedAmount.decrypt` to read amounts
	 * from event payloads.
	 *
	 * @throws on the same conditions as `recoverPrivateKey`.
	 */
	async getTokenAccount(address: string): Promise<TokenAccount> {
		const tokenAccountId = getTokenAccountId(this.#packageConfig, address, this.#tokenType);

		const { object } = await this.#suiClient.core.getObject({
			objectId: tokenAccountId,
			include: { content: true },
		});

		const parsed = TokenAccountField.parse(object.content).value;
		const verified = {
			ciphertext: parsed.verified_key_encryption.ciphertext.map((raw) =>
				MultiRecipientEncryption.fromBcs(raw),
			),
			version: parsed.verified_key_encryption.version,
		};
		const privateKey = this.recoverPrivateKey(verified, pointFromBcs(parsed.pk));
		return new TokenAccount(address, this.#tokenType, this.#packageConfig, privateKey);
	}
}

const TokenAccountField = DynamicField(
	contraContracts.TokenAccountKey,
	contraContracts.TokenAccount,
);
