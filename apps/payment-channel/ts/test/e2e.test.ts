// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { createContraAccount, waitForSui } from 'contra-utils';
import { ContraClient, DiscreteLogTable, TokenAccount } from 'ts-sdk';
import { beforeAll, describe, expect, it } from 'vitest';

import { PaymentChannelClient } from '../src/client.ts';
import { deployBundle, type Deployment } from '../src/deploy.ts';
import { Receiver } from '../src/receiver.ts';
import { Sender } from '../src/sender.ts';
import {
	createChannel,
	fundAndActivateChannel,
	pickSuiGasCoin,
	setupChannelContraAccount,
} from '../src/setup.ts';

const NETWORK = 'devnet';

describe('payment_channel e2e', () => {
	let suiClient: SuiJsonRpcClient;
	let deployer: Ed25519Keypair;
	let senderKp: Ed25519Keypair;
	let receiverKp: Ed25519Keypair;
	let deployment: Deployment;
	let contraClient: ContraClient;
	let paymentChannelClient: PaymentChannelClient;
	let table: DiscreteLogTable;
	let senderTokenAccount: TokenAccount;
	let receiverTokenAccount: TokenAccount;
	let channelObjectId: string;
	let channelTokenAccount: TokenAccount;
	const lockedAmount = 100n;

	beforeAll(async () => {
		suiClient = new SuiJsonRpcClient({
			url: getJsonRpcFullnodeUrl(NETWORK),
			network: NETWORK,
		});

		deployer = Ed25519Keypair.generate();
		senderKp = Ed25519Keypair.generate();
		receiverKp = Ed25519Keypair.generate();
		for (const kp of [deployer, senderKp, receiverKp]) {
			await requestSuiFromFaucetV2({
				host: getFaucetHost(NETWORK),
				recipient: kp.toSuiAddress(),
			});
			await waitForSui(suiClient, kp.toSuiAddress());
		}

		deployment = await deployBundle({ suiClient, deployer });

		table = DiscreteLogTable.create(16);
		contraClient = new ContraClient({
			suiClient,
			packageConfig: deployment.contra,
			table,
		});
		paymentChannelClient = new PaymentChannelClient({
			suiClient,
			config: deployment.paymentChannel,
		});

		// Wallet contra accounts (sender's is also the sweep destination).
		senderTokenAccount = await createContraAccount(
			suiClient,
			contraClient,
			deployment.contra,
			senderKp,
			deployment.buType,
		);
		receiverTokenAccount = await createContraAccount(
			suiClient,
			contraClient,
			deployment.contra,
			receiverKp,
			deployment.buType,
		);

		// Create the channel (state = Initialized), then bring up its contra
		// account, then fund + activate.
		const created = await createChannel({
			suiClient,
			paymentChannelClient,
			tokenType: deployment.buType,
			senderKp,
		});
		channelObjectId = created.channelObjectId;
		channelTokenAccount = await setupChannelContraAccount({
			suiClient,
			contraClient,
			paymentChannelClient,
			deployment,
			senderKp,
			channelObjectId,
		});
		const endTimeMs = BigInt(Date.now() + 10 * 60_000);
		await fundAndActivateChannel({
			suiClient,
			contraClient,
			paymentChannelClient,
			deployment,
			senderKp,
			channelObjectId,
			receiverAddress: receiverKp.toSuiAddress(),
			endTimeMs,
			fundAmount: lockedAmount,
		});
	});

	function makeSender() {
		return new Sender({
			suiClient,
			contraClient,
			paymentChannelClient,
			walletKeypair: senderKp,
			tokenType: deployment.buType,
			channelObjectId,
			channelTokenAccount,
			receiverAddress: receiverKp.toSuiAddress(),
			sweepDestAddress: senderTokenAccount.address,
		});
	}

	function makeReceiver() {
		return new Receiver({
			suiClient,
			walletKeypair: receiverKp,
			contraTokenAccount: receiverTokenAccount,
			tokenType: deployment.buType,
			channelAddress: channelObjectId,
			contraPackageId: deployment.contra.packageId,
			table,
		});
	}

	it('sender cannot sweep while channel is open and receiver has not settled', async () => {
		const sender = makeSender();
		const senderGas = await pickSuiGasCoin(suiClient, senderKp.toSuiAddress());
		const res = await sender.sweep(senderGas);
		expect(res.effects?.status?.status).toBe('failure');
		const err = res.effects?.status?.error ?? '';
		// MoveAbort in payment_channel with code 2 (EChannelActive).
		expect(err).toMatch(/payment_channel/);
		expect(err).toMatch(/, 2\)/);
	});

	it('receiver settles, then sender sweeps the residual without waiting for end_time', async () => {
		const sender = makeSender();
		const receiver = makeReceiver();

		const recvGas = await pickSuiGasCoin(suiClient, receiverKp.toSuiAddress());
		const t1 = await sender.transfer(20n, recvGas);
		await receiver.update(20n, t1);
		const t2 = await sender.transfer(15n, recvGas);
		await receiver.update(15n, t2);
		expect(receiver.getAccumulated()).toBe(35n);

		const settled = await receiver.settle();
		expect(settled.effects?.status?.status).toBe('success');
		await suiClient.waitForTransaction({ digest: settled.digest });
		const failed = (settled.events ?? []).find((e) =>
			e.type.endsWith('::events::TryTransferFailedEvent'),
		);
		expect(failed, 'channel transfer should not have hit TryTransferFailedEvent').toBeUndefined();

		const recvBal = await contraClient.getBalance(receiverTokenAccount);
		expect(recvBal.pending.amount).toBe(35n);

		// Sender, now that the channel is Closed, can sweep the residual.
		const senderGas = await pickSuiGasCoin(suiClient, senderKp.toSuiAddress());
		const sweep = await sender.sweep(senderGas);
		expect(sweep.effects?.status?.status).toBe('success');
		await suiClient.waitForTransaction({ digest: sweep.digest });
		const sweepFailed = (sweep.events ?? []).find((e) =>
			e.type.endsWith('::events::TryTransferFailedEvent'),
		);
		expect(sweepFailed, 'sweep should not have hit TryTransferFailedEvent').toBeUndefined();

		const senderBal = await contraClient.getBalance(senderTokenAccount);
		expect(senderBal.pending.amount).toBe(lockedAmount - 35n);
	});
});
