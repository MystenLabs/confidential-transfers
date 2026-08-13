// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ClientWithCoreApi } from '@mysten/sui/client';
import { type Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { executeOrThrow } from 'contra-utils';
import { ContraClient, contraContracts, TokenAccount } from 'ts-sdk';

import { PaymentChannelClient } from './client.ts';
import { type Deployment } from './deploy.ts';

/** Pick the first SUI coin owned by `owner` to use as gas payment. */
export async function pickSuiGasCoin(
	suiClient: ClientWithCoreApi,
	owner: string,
): Promise<{ objectId: string; version: string; digest: string }> {
	const { objects } = await suiClient.core.listCoins({
		owner,
		coinType: '0x2::sui::SUI',
	});
	if (objects.length === 0) throw new Error(`no SUI coins owned by ${owner}`);
	const c = objects[0];
	return { objectId: c.objectId, version: c.version, digest: c.digest };
}

/**
 * Create + share an empty `Channel<T>` (state = `Initialized`). Returns the
 * channel's object id; since a `Channel<T>`'s id equals its UID address,
 * `channelObjectId` is also the contra-account owner address.
 */
export async function createChannel(opts: {
	suiClient: ClientWithCoreApi;
	paymentChannelClient: PaymentChannelClient;
	tokenType: string;
	senderKp: Ed25519Keypair;
}): Promise<{ channelObjectId: string }> {
	const { suiClient, paymentChannelClient, tokenType, senderKp } = opts;
	const tx = new Transaction();
	tx.add(paymentChannelClient.newChannel({ tokenType }));
	const executed = await executeOrThrow(suiClient, tx, senderKp, 'createChannel');

	const created = executed.effects.changedObjects.find(
		(c) =>
			c.idOperation === 'Created' &&
			executed.objectTypes[c.objectId]?.includes('::payment_channel::Channel<'),
	);
	if (!created) throw new Error('no Channel created');
	return { channelObjectId: created.objectId };
}

/**
 * Bring up the channel's contra account in a single PTB:
 *   1. `payment_channel::get_auth(channel)` → `Auth<T>`
 *   2. `contra::new_account(registry, channel_address)` → `Account`
 *   3. `contra::register(...)` with the channel's pk and the auth from step 1
 *   4. `contra::share_account(account)`
 *
 * Returns the freshly registered `TokenAccount` for the channel.
 */
export async function setupChannelContraAccount(opts: {
	suiClient: ClientWithCoreApi;
	contraClient: ContraClient;
	paymentChannelClient: PaymentChannelClient;
	deployment: Deployment;
	senderKp: Ed25519Keypair;
	channelObjectId: string;
}): Promise<TokenAccount> {
	const { suiClient, contraClient, paymentChannelClient, deployment, senderKp, channelObjectId } =
		opts;
	const channelTokenAccount = new TokenAccount(
		channelObjectId,
		deployment.buType,
		deployment.contra,
	);

	const tx = new Transaction();
	const channelArg = tx.object(channelObjectId);
	const auth = tx.add(
		paymentChannelClient.getAuth({
			channel: channelArg,
			tokenType: deployment.buType,
		}),
	);
	// Account creation is owner-only; the channel self-authenticates via its `&mut UID` inside
	// `payment_channel::new_account`, so the account is created there rather than via `newAccount`.
	const account = tx.moveCall({
		target: `${deployment.packageId}::payment_channel::new_account`,
		typeArguments: [deployment.buType],
		arguments: [channelArg, tx.object(deployment.contra.accountRegistryId)],
	});
	tx.add(
		await contraClient.register({
			tokenAccount: channelTokenAccount,
			account,
			auth: () => auth,
		}),
	);
	tx.add(
		contraContracts.shareAccount({
			package: deployment.contra.packageId,
			arguments: { account },
		}),
	);

	await executeOrThrow(suiClient, tx, senderKp, 'setupChannelContraAccount');
	return channelTokenAccount;
}

/**
 * Fund the channel's contra account and activate the channel. Done in two
 * txs because `bu::mint_10` transfers the freshly minted coin to the caller's
 * wallet (so the wrap can't chain into the same PTB):
 *   tx1: `bu::mint_10`,
 *   tx2: split → `contra::wrap` → `payment_channel::activate`.
 *
 * No upfront merge: the wrapped funds sit in the channel account's pending
 * balance until the first settlement, whose `transfer({ merge: true })` call
 * prepends a merge under the channel auth. The "merge succeeded but transfer
 * failed" race that motivates `merge: false` elsewhere can't fire here —
 * only the channel sender deposits, and they stop after activate.
 */
export async function fundAndActivateChannel(opts: {
	suiClient: ClientWithCoreApi;
	contraClient: ContraClient;
	paymentChannelClient: PaymentChannelClient;
	deployment: Deployment;
	senderKp: Ed25519Keypair;
	channelObjectId: string;
	receiverAddress: string;
	endTimeMs: bigint;
	fundAmount: bigint;
}): Promise<void> {
	const {
		suiClient,
		contraClient,
		paymentChannelClient,
		deployment,
		senderKp,
		channelObjectId,
		receiverAddress,
		endTimeMs,
		fundAmount,
	} = opts;
	const MINT_10_AMOUNT = 10_000_000_000n;
	if (fundAmount > MINT_10_AMOUNT) {
		throw new Error(`fundAmount ${fundAmount} exceeds one mint_10 (${MINT_10_AMOUNT})`);
	}

	// 1. Mint BU into the sender's wallet.
	const mintTx = new Transaction();
	mintTx.moveCall({
		target: `${deployment.packageId}::bu::mint_10`,
		arguments: [mintTx.object(deployment.buTreasuryId)],
	});
	await executeOrThrow(suiClient, mintTx, senderKp, 'mint_10');

	const { objects } = await suiClient.core.listCoins({
		owner: senderKp.toSuiAddress(),
		coinType: deployment.buType,
	});
	if (objects.length === 0) throw new Error('no BU coin found after mint_10');

	// 2. Split + wrap into channel, then activate.
	const tx = new Transaction();
	const [split] = tx.splitCoins(tx.object(objects[0].objectId), [tx.pure.u64(fundAmount)]);
	tx.add(
		await contraClient.wrap({
			coin: split,
			receiver: channelObjectId,
			tokenType: deployment.buType,
		}),
	);
	tx.add(
		paymentChannelClient.activate({
			channel: tx.object(channelObjectId),
			receiver: receiverAddress,
			endTimeMs,
			tokenType: deployment.buType,
		}),
	);
	await executeOrThrow(suiClient, tx, senderKp, 'fundAndActivate');
}
