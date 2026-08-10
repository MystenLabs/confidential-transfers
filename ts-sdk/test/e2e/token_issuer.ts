// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { join } from 'node:path';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import {
	compileMovePackage,
	ContraInitializer,
	findObject,
	patchMoveToml,
	publishBytecodes,
	signExecuteAndWait,
	type Bytecodes,
} from 'contra-utils/node';

import * as contraContracts from '../../src/contracts/contra/contra.js';
import { buildPublicKeyVector } from '../../src/helpers.js';
import { G } from '../../src/ristretto255.js';
import type { RistrettoPoint } from '../../src/ristretto255.js';

/**
 * Token issuer: publishes a coin and registers it as a confidential token.
 * A separate actor from the protocol initializer; holds the coin's
 * TreasuryCap and ManagementCap, and tracks the single per-transfer auditor
 * key it has currently set on chain.
 *
 * The token is registered with no auditor key; call `setAuditorKey(sk)` to
 * set or replace it, or `setAuditorKey()` to disable auditing.
 */
export class TokenIssuer {
	#auditorPrivateKey?: bigint;
	#auditorPublicKey?: RistrettoPoint;

	private constructor(
		readonly client: SuiGrpcClient,
		readonly keypair: Ed25519Keypair,
		readonly address: string,
		readonly tokenType: string,
		readonly treasuryCapId: string,
		readonly confidentialTokenId: string,
		readonly managementCapId: string,
		readonly denyCapId: string,
		readonly contraPackageId: string,
		readonly freezeAdminKeypair: Ed25519Keypair,
		readonly freezeAdminAddress: string,
	) {}

	/** The current auditor private key, or `undefined` when auditing is disabled. */
	get auditorPrivateKey(): bigint | undefined {
		return this.#auditorPrivateKey;
	}

	/** The current auditor public key, or `undefined` when auditing is disabled. */
	get auditorPublicKey(): RistrettoPoint | undefined {
		return this.#auditorPublicKey;
	}

	/**
	 * Fund a fresh issuer keypair, publish the MYCOIN test coin, and register
	 * it as a confidential token with no auditor keys (version 0).
	 */
	static async init(
		contra: ContraInitializer,
		log: (msg: string) => void = console.log,
	): Promise<TokenIssuer> {
		const { client, contraPackageId, tokenRegistryId } = contra;

		// 1. Create a new keypair for the token issuer.
		const keypair = Ed25519Keypair.generate();
		const address = keypair.getPublicKey().toSuiAddress();
		log(`Token issuer address: ${address}`);

		// Fund the token issuer from the protocol initializer rather than the
		// devnet faucet directly. The e2e suites run in parallel, so routing
		// issuer funding through the initializer keeps faucet requests to one
		// per suite — matching `ContraInitializer`'s documented role as the
		// SUI faucet stand-in for test participants.
		await contra.fund(address, 2_000_000_000n);
		log('Funded token issuer from the protocol initializer');

		// 2. Compile and publish the MYCOIN coin.
		const mycoinPath = join(import.meta.dirname, 'move', 'mycoin');
		const restoreMycoinToml = patchMoveToml(mycoinPath);
		log('Compiling MYCOIN...');
		let mycoinBytecodes: Bytecodes;
		try {
			mycoinBytecodes = compileMovePackage(mycoinPath);
		} finally {
			restoreMycoinToml();
		}
		log('Publishing MYCOIN...');
		const mycoinResult = await publishBytecodes(mycoinBytecodes, keypair, client);
		const treasuryCapId = findObject(mycoinResult.createdObjects, 'TreasuryCap');
		const denyCapId = findObject(mycoinResult.createdObjects, 'DenyCapV2');
		const tokenType = `${mycoinResult.packageId}::mycoin::MYCOIN`;
		log(`MYCOIN: ${tokenType}`);

		// 3. Register MYCOIN as a confidential token with no auditors.
		log('Registering MYCOIN as confidential token (no auditors)...');
		const regTx = new Transaction();
		const [ct, managementCap] = regTx.add(
			contraContracts.newConfidentialToken({
				package: contraPackageId,
				typeArguments: [tokenType],
				arguments: {
					registry: tokenRegistryId,
					T: treasuryCapId,
					auditorPublicKeys: buildPublicKeyVector(contraPackageId, []),
				},
			}),
		);
		regTx.add(
			contraContracts.shareConfidentialToken({
				package: contraPackageId,
				typeArguments: [tokenType],
				arguments: { ct },
			}),
		);
		regTx.transferObjects([managementCap], address);
		const created = await signExecuteAndWait(regTx, keypair, client);
		const confidentialTokenId = findObject(created, 'ConfidentialToken');
		const managementCapId = findObject(created, 'ManagementCap');
		log('Confidential token registered');

		// 4. Create a separate keypair for the global freeze admin and grant
		//    it the global freeze capability in its own transaction.
		const freezeAdminKeypair = Ed25519Keypair.generate();
		const freezeAdminAddress = freezeAdminKeypair.getPublicKey().toSuiAddress();
		log(`Freeze admin address: ${freezeAdminAddress}`);

		log('Granting global freeze capability to freeze admin (and funding it)...');
		const freezeTx = new Transaction();
		// The freeze admin signs its own txs in tests; fund it with a small amount
		// of SUI for gas in the same PTB that grants the freeze capability.
		const [fundCoin] = freezeTx.splitCoins(freezeTx.gas, [50_000_000n]);
		freezeTx.transferObjects([fundCoin], freezeAdminAddress);
		freezeTx.add(
			contraContracts.issueFreezeCap({
				package: contraPackageId,
				typeArguments: [tokenType],
				arguments: {
					ct: confidentialTokenId,
					T: managementCapId,
					addr: freezeAdminAddress,
				},
			}),
		);
		freezeTx.setSender(address);
		await signExecuteAndWait(freezeTx, keypair, client);
		log('Freeze admin granted and funded');

		return new TokenIssuer(
			client,
			keypair,
			address,
			tokenType,
			treasuryCapId,
			confidentialTokenId,
			managementCapId,
			denyCapId,
			contraPackageId,
			freezeAdminKeypair,
			freezeAdminAddress,
		);
	}

	/** Mint `amount` of the underlying coin to `recipient`. */
	async mint(recipient: string, amount: bigint): Promise<void> {
		await this.mintMany([{ recipient, amount }]);
	}

	/**
	 * Mint to several recipients in a single transaction. Folding the mints
	 * into one PTB avoids serializing one issuer-signed tx per recipient.
	 */
	async mintMany(mints: ReadonlyArray<{ recipient: string; amount: bigint }>): Promise<void> {
		const tx = new Transaction();
		for (const { recipient, amount } of mints) {
			tx.moveCall({
				target: '0x2::coin::mint_and_transfer',
				typeArguments: [this.tokenType],
				arguments: [tx.object(this.treasuryCapId), tx.pure.u64(amount), tx.pure.address(recipient)],
			});
		}
		tx.setSender(this.address);
		await signExecuteAndWait(tx, this.keypair, this.client);
	}

	/**
	 * Set the token's per-transfer auditor key on chain via `update_auditors`. Pass a private key to
	 * enable auditing under it (as a single-auditor set, `current == previous`); omit it to disable
	 * auditing (both vectors empty).
	 */
	async setAuditorKey(privateKey?: bigint): Promise<void> {
		const publicKey = privateKey === undefined ? undefined : G.multiply(privateKey);
		const pks = publicKey ? [publicKey] : [];

		const tx = new Transaction();
		tx.add(
			contraContracts.updateAuditors({
				package: this.contraPackageId,
				typeArguments: [this.tokenType],
				arguments: {
					ct: this.confidentialTokenId,
					Cap: this.managementCapId,
					currentPks: buildPublicKeyVector(this.contraPackageId, pks),
					previousPks: buildPublicKeyVector(this.contraPackageId, pks),
				},
			}),
		);
		tx.setSender(this.address);
		await signExecuteAndWait(tx, this.keypair, this.client);

		this.#auditorPrivateKey = privateKey;
		this.#auditorPublicKey = publicKey;
	}
}
