// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

import { compileMovePackage } from './node.js';
import { findObject, publishBytecodes, signExecuteAndWait } from './publish.js';

/** Networks `ContraInitializer` can publish against. */
export type ContraNetwork = 'devnet' | 'testnet';

/**
 * Protocol initializer: publishes the contra Move package (on `devnet` by
 * default) and stands in as the SUI faucet for test participants. Holds the
 * protocol-initializer keypair, the published package id, and the shared
 * registries.
 */
export class ContraInitializer {
	private constructor(
		readonly client: SuiJsonRpcClient,
		readonly keypair: Ed25519Keypair,
		readonly address: string,
		readonly contraPackageId: string,
		readonly accountRegistryId: string,
		readonly tokenRegistryId: string,
	) {}

	/**
	 * One-time protocol setup: fund a fresh keypair from the faucet, compile
	 * the contra package at `contraMoveDir`, publish it, and locate the
	 * registries created by `init`. Targets `devnet` unless `network` says
	 * otherwise.
	 */
	static async init(opts: {
		/** Absolute path to the contra Move package (the dir containing its `Move.toml`). */
		contraMoveDir: string;
		/** Network to fund/publish against. Defaults to `devnet`. */
		network?: ContraNetwork;
		log?: (msg: string) => void;
	}): Promise<ContraInitializer> {
		const log = opts.log ?? console.log;
		const network = opts.network ?? 'devnet';
		const client = new SuiJsonRpcClient({
			url: getJsonRpcFullnodeUrl(network),
			network,
		});

		const keypair = Ed25519Keypair.generate();
		const address = keypair.getPublicKey().toSuiAddress();
		log(`Protocol initializer address: ${address}`);

		const faucetResp = await requestSuiFromFaucetV2({
			host: getFaucetHost(network),
			recipient: address,
		});
		if (
			faucetResp.status !== 'Success' ||
			!faucetResp.coins_sent ||
			faucetResp.coins_sent.length === 0
		) {
			throw new Error(`Faucet returned no coins: ${JSON.stringify(faucetResp.status)}`);
		}
		// The faucet response only confirms that the transfer tx was submitted;
		// the coins are not yet visible on the fullnode RPC we'll publish
		// against. Without this wait, `publishBytecodes` races and aborts with
		// "No valid gas coins found for the transaction."
		await Promise.all(
			faucetResp.coins_sent.map((coin) =>
				client.waitForTransaction({ digest: coin.transferTxDigest }),
			),
		);
		log('Funded protocol initializer from faucet');

		log('Compiling contra package...');
		const bytecodes = compileMovePackage(opts.contraMoveDir, { env: network });
		log('Publishing contra package...');
		const result = await publishBytecodes(bytecodes, keypair, client);
		const accountRegistryId = findObject(result.createdObjects, 'AccountRegistry');
		const tokenRegistryId = findObject(result.createdObjects, 'TokenRegistry');
		log(`Contra package: ${result.packageId}`);

		return new ContraInitializer(
			client,
			keypair,
			address,
			result.packageId,
			accountRegistryId,
			tokenRegistryId,
		);
	}

	/** Send `amount` MIST of SUI from the initializer to `recipient`. */
	async fund(recipient: string, amount: bigint): Promise<void> {
		const tx = new Transaction();
		const [coin] = tx.splitCoins(tx.gas, [amount]);
		tx.transferObjects([coin], recipient);
		tx.setSender(this.address);
		await signExecuteAndWait(tx, this.keypair, this.client);
	}
}
