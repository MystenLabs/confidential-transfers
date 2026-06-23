// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Wraps the test-only `gated` Move module, which exposes the permissioned
 * (`with_witness`) and object-bound (`as_object`) auth wrappers around
 * `contra::contra`. `Gated.publish` compiles and deploys the module; the
 * instance methods drive the gated registration / vault flows and the token
 * policy that activates them.
 *
 * Mirrors `TokenIssuer` and `Admin` as a small operation wrapper: each method
 * builds the Move call, signs it with the right authority, and executes it.
 */

import { join } from 'node:path';
import { bcs } from '@mysten/sui/bcs';
import { Transaction } from '@mysten/sui/transactions';
import { deriveObjectID, SUI_DENY_LIST_OBJECT_ID } from '@mysten/sui/utils';
import {
	compileMovePackage,
	patchMoveToml,
	patchPublishedToml,
	publishBytecodes,
} from 'contra-utils/node';

import { getBulletproofs } from '../../src/bp.js';
import * as contraContracts from '../../src/contracts/contra/contra.js';
import {
	buildKeyEncryptionOption,
	point,
	PROTOCOL_KEY_CONSISTENCY,
	PROTOCOL_KEY_RANGE_PROOF,
} from '../../src/helpers.js';
import { KeyEncryption } from '../../src/key_encryption.js';
import type { TokenAccount } from '../../src/token_account.js';
import type { ContraTestClient, FreshUser, Harness, Signer } from './harness.js';
import type { TokenIssuer } from './token_issuer.js';

/**
 * The deployed `gated` test module, plus the operations that exercise the
 * permissioned-auth paths it wraps.
 */
export class Gated {
	private constructor(
		/** The published `gated` package id. */
		readonly packageId: string,
		private readonly tokenIssuer: TokenIssuer,
		private readonly client: ContraTestClient,
		private readonly exec: Harness['exec'],
	) {}

	/**
	 * Compile and publish the `gated` module, linking it against the
	 * freshly-published contra package via a temporary `Published.toml`
	 * entry so its `with_witness` / `as_object` wrappers resolve to the same
	 * on-chain code the rest of the suite uses.
	 */
	static async publish(
		contraInit: Harness['contraInit'],
		tokenIssuer: TokenIssuer,
		client: ContraTestClient,
		exec: Harness['exec'],
	): Promise<Gated> {
		const contraMoveDir = join(import.meta.dirname, '..', '..', '..', 'move');
		const gatedMoveDir = join(import.meta.dirname, 'move', 'gated');
		const restorePublishedToml = patchPublishedToml(contraMoveDir, contraInit.contraPackageId);
		const restoreGatedToml = patchMoveToml(gatedMoveDir);
		try {
			const bytecodes = compileMovePackage(gatedMoveDir);
			const result = await publishBytecodes(bytecodes, contraInit.keypair, contraInit.client);
			return new Gated(result.packageId, tokenIssuer, client, exec);
		} finally {
			restoreGatedToml();
			restorePublishedToml();
		}
	}

	/** The witness type tag passed to `contra::set_policy<T, GatedWitness>`. */
	get witnessType(): string {
		return `${this.packageId}::gated::GatedWitness`;
	}

	/**
	 * Gate `operations` behind `GatedWitness` via `contra::set_policy`. Pass
	 * an empty array to clear the policy (fully permissionless again).
	 * Signed by the issuer.
	 */
	async setPolicy(operations: number[]): Promise<void> {
		const tx = new Transaction();
		tx.add(
			contraContracts.setPolicy({
				package: this.tokenIssuer.contraPackageId,
				typeArguments: [this.tokenIssuer.tokenType, this.witnessType],
				arguments: {
					ct: this.tokenIssuer.confidentialTokenId,
					T: this.tokenIssuer.treasuryCapId,
					permissionedOperations: operations,
				},
			}),
		);
		tx.setSender(this.tokenIssuer.address);
		await this.exec(tx, this.tokenIssuer.keypair);
	}

	/**
	 * Register `user`'s token account via `gated::gated_register`, which
	 * builds an `Auth` through `with_witness`. The account must already be
	 * created and shared. Signed by `user`.
	 */
	async register(user: FreshUser): Promise<void> {
		const keyEncryption = await this.#keyEncryption(user.tokenAccount);
		const tx = new Transaction();
		tx.moveCall({
			target: `${this.packageId}::gated::gated_register`,
			typeArguments: [this.tokenIssuer.tokenType],
			arguments: [
				tx.object(this.tokenIssuer.confidentialTokenId),
				tx.object(this.client.contra.getAccountId(user.address)),
				point(user.tokenAccount.publicKey.toBytes()),
				buildKeyEncryptionOption(this.tokenIssuer.contraPackageId, keyEncryption),
			],
		});
		tx.setSender(user.address);
		await this.exec(tx, user.keypair);
	}

	/** Create and share a `Vault`; returns its object id. Signed by `signer`. */
	async createVault(signer: Signer): Promise<string> {
		const tx = new Transaction();
		const vault = tx.moveCall({ target: `${this.packageId}::gated::new_vault`, arguments: [] });
		tx.moveCall({ target: `${this.packageId}::gated::share_vault`, arguments: [vault] });
		tx.setSender(signer.address);
		const result = await this.exec(tx, signer.keypair);
		// The vault is the only object created by this PTB.
		const created = result.Transaction!.effects!.changedObjects.find(
			(o) => o.idOperation === 'Created',
		);
		if (!created) throw new Error('Vault was not created');
		return created.objectId;
	}

	/**
	 * Create and share the contra `Account` for `vault`'s address, then
	 * register `tokenAccount` inside it via `gated::vault_register`
	 * (object-bound auth). Signed by `signer`.
	 */
	async vaultRegister(vault: string, tokenAccount: TokenAccount, signer: Signer): Promise<void> {
		const keyEncryption = await this.#keyEncryption(tokenAccount);
		const tx = new Transaction();
		const account = tx.add(this.client.contra.newAccount({ owner: vault }));
		tx.moveCall({
			target: `${this.packageId}::gated::vault_register`,
			typeArguments: [this.tokenIssuer.tokenType],
			arguments: [
				tx.object(vault),
				tx.object(this.tokenIssuer.confidentialTokenId),
				account,
				point(tokenAccount.publicKey.toBytes()),
				buildKeyEncryptionOption(this.tokenIssuer.contraPackageId, keyEncryption),
			],
		});
		tx.add(this.client.contra.shareAccount({ account }));
		tx.setSender(signer.address);
		await this.exec(tx, signer.keypair);
	}

	/**
	 * Wrap `amount` of the first MYCOIN coin owned by `signer` into `vault`'s
	 * token account via `gated::vault_wrap` (object-bound auth).
	 */
	async vaultWrap(vault: string, amount: bigint, signer: Signer): Promise<void> {
		const pid = this.tokenIssuer.contraPackageId;
		const coins = await this.client.getCoins({
			owner: signer.address,
			coinType: this.tokenIssuer.tokenType,
		});
		if (coins.data.length === 0) throw new Error('no coins to wrap');

		const poolId = deriveObjectID(
			this.tokenIssuer.confidentialTokenId,
			`${pid}::contra::PoolKey`,
			bcs.byteVector().serialize([]).toBytes(),
		);

		const tx = new Transaction();
		const [coin] = tx.splitCoins(tx.object(coins.data[0].coinObjectId), [amount]);
		tx.moveCall({
			target: `${this.packageId}::gated::vault_wrap`,
			typeArguments: [this.tokenIssuer.tokenType],
			arguments: [
				tx.object(vault),
				tx.object(this.client.contra.getAccountId(vault)),
				tx.object(this.tokenIssuer.confidentialTokenId),
				tx.object(SUI_DENY_LIST_OBJECT_ID),
				tx.object(poolId),
				coin,
				tx.pure.vector('u8', []),
			],
		});
		tx.setSender(signer.address);
		await this.exec(tx, signer.keypair);
	}

	/**
	 * Wrap `amount` of the first MYCOIN coin owned by `receiver` into
	 * `receiver`'s own token account via `gated::gated_wrap`, which builds an
	 * `Auth` through `with_witness` for the `WRAP` operation. Signed by
	 * `receiver`.
	 */
	async wrap(receiver: FreshUser, amount: bigint): Promise<void> {
		const pid = this.tokenIssuer.contraPackageId;
		const coins = await this.client.getCoins({
			owner: receiver.address,
			coinType: this.tokenIssuer.tokenType,
		});
		if (coins.data.length === 0) throw new Error('no coins to wrap');

		const poolId = deriveObjectID(
			this.tokenIssuer.confidentialTokenId,
			`${pid}::contra::PoolKey`,
			bcs.byteVector().serialize([]).toBytes(),
		);

		const tx = new Transaction();
		const [coin] = tx.splitCoins(tx.object(coins.data[0].coinObjectId), [amount]);
		tx.moveCall({
			target: `${this.packageId}::gated::gated_wrap`,
			typeArguments: [this.tokenIssuer.tokenType],
			arguments: [
				tx.object(this.client.contra.getAccountId(receiver.address)),
				tx.object(this.tokenIssuer.confidentialTokenId),
				tx.object(SUI_DENY_LIST_OBJECT_ID),
				tx.object(poolId),
				coin,
				tx.pure.vector('u8', []),
			],
		});
		tx.setSender(receiver.address);
		await this.exec(tx, receiver.keypair);
	}

	/** Build the `KeyEncryption` for `tokenAccount` against the current auditor set, if any. */
	async #keyEncryption(tokenAccount: TokenAccount): Promise<KeyEncryption | undefined> {
		const auditorPks = this.tokenIssuer.getAuditorKeys(this.tokenIssuer.auditorVersion).publicKeys;
		if (auditorPks.length === 0) return undefined;
		const { batchRangeProver } = await getBulletproofs();
		return KeyEncryption.prove(
			batchRangeProver,
			tokenAccount.dst(PROTOCOL_KEY_CONSISTENCY),
			tokenAccount.dst(PROTOCOL_KEY_RANGE_PROOF),
			tokenAccount.privateKey,
			tokenAccount.publicKey,
			auditorPks,
		);
	}
}
