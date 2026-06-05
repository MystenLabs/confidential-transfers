// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { type Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { ContraClient, contraContracts, TokenAccount } from 'ts-sdk';

import { PaymentChannelClient } from './client.ts';
import { type Deployment } from './deploy.ts';

/** Pick the first SUI coin owned by `owner` to use as gas payment. */
export async function pickSuiGasCoin(
	suiClient: SuiJsonRpcClient,
	owner: string,
): Promise<{ objectId: string; version: string; digest: string }> {
	const { data } = await suiClient.getCoins({
		owner,
		coinType: '0x2::sui::SUI',
	});
	if (data.length === 0) throw new Error(`no SUI coins owned by ${owner}`);
	const c = data[0];
	return { objectId: c.coinObjectId, version: c.version, digest: c.digest };
}

/**
 * Create + share an empty `Channel<T>` (state = `Initialized`). Returns the
 * channel's object id; since a `Channel<T>`'s id equals its UID address,
 * `channelObjectId` is also the contra-account owner address.
 */
export async function createChannel(opts: {
	suiClient: SuiJsonRpcClient;
	paymentChannelClient: PaymentChannelClient;
	tokenType: string;
	senderKp: Ed25519Keypair;
}): Promise<{ channelObjectId: string }> {
	const { suiClient, paymentChannelClient, tokenType, senderKp } = opts;
	const tx = new Transaction();
	tx.add(paymentChannelClient.newChannel({ tokenType }));
	const res = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: senderKp,
		options: { showEffects: true, showObjectChanges: true },
	});
	if (res.effects?.status?.status !== 'success') {
		throw new Error(`createChannel failed: ${JSON.stringify(res.effects?.status)}`);
	}
	await suiClient.waitForTransaction({ digest: res.digest });

	const created = (res.objectChanges ?? []).find(
		(c) => c.type === 'created' && c.objectType.includes('::payment_channel::Channel<'),
	);
	if (!created || created.type !== 'created') throw new Error('no Channel created');
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
	suiClient: SuiJsonRpcClient;
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
	const account = tx.add(
		contraContracts.newAccount({
			package: deployment.contra.packageId,
			arguments: { registry: deployment.contra.accountRegistryId, owner: channelObjectId },
		}),
	);
	tx.add(
		await contraClient.register({
			tokenAccount: channelTokenAccount,
			account,
			auditorPublicKeys: [],
			auth: () => auth,
		}),
	);
	tx.add(
		contraContracts.shareAccount({
			package: deployment.contra.packageId,
			arguments: { account },
		}),
	);

	const res = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: senderKp,
		options: { showEffects: true },
	});
	if (res.effects?.status?.status !== 'success') {
		throw new Error(`setupChannelContraAccount failed: ${JSON.stringify(res.effects?.status)}`);
	}
	await suiClient.waitForTransaction({ digest: res.digest });
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
	suiClient: SuiJsonRpcClient;
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
	const mintRes = await suiClient.signAndExecuteTransaction({
		transaction: mintTx,
		signer: senderKp,
		options: { showEffects: true },
	});
	if (mintRes.effects?.status?.status !== 'success') {
		throw new Error(`mint_10 failed: ${JSON.stringify(mintRes.effects?.status)}`);
	}
	await suiClient.waitForTransaction({ digest: mintRes.digest });

	const { data } = await suiClient.getCoins({
		owner: senderKp.toSuiAddress(),
		coinType: deployment.buType,
	});
	if (data.length === 0) throw new Error('no BU coin found after mint_10');

	// 2. Split + wrap into channel, then activate.
	const tx = new Transaction();
	const [split] = tx.splitCoins(tx.object(data[0].coinObjectId), [tx.pure.u64(fundAmount)]);
	tx.add(
		contraClient.wrap({
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
	const res = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: senderKp,
		options: { showEffects: true },
	});
	if (res.effects?.status?.status !== 'success') {
		throw new Error(`fundAndActivate failed: ${JSON.stringify(res.effects?.status)}`);
	}
	await suiClient.waitForTransaction({ digest: res.digest });
}
