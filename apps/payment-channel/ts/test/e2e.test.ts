// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { createContraAccount, grpcClientFor, waitForSui } from 'contra-utils';
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
	let suiClient: SuiGrpcClient;
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
	// The token's published auditor-rotation grace period (see the Receiver class doc).
	const GRACE_PERIOD_MS = 24n * 60n * 60n * 1000n;

	beforeAll(async () => {
		suiClient = grpcClientFor(NETWORK);

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

	async function makeReceiver() {
		const receiver = new Receiver({
			suiClient,
			walletKeypair: receiverKp,
			contraTokenAccount: receiverTokenAccount,
			tokenType: deployment.buType,
			channelAddress: channelObjectId,
			contraPackageId: deployment.contra.packageId,
			paymentChannelPackageId: deployment.paymentChannel.paymentChannelPackageId,
			confidentialTokenId: deployment.confidentialTokenId,
			auditorPk: null,
			gracePeriodMs: GRACE_PERIOD_MS,
			table,
		});
		await receiver.init();
		return receiver;
	}

	it('sender cannot sweep while channel is open and receiver has not settled', async () => {
		const sender = makeSender();
		const senderGas = await pickSuiGasCoin(suiClient, senderKp.toSuiAddress());
		// The gRPC client resolves transactions via simulation during build, so
		// the EChannelActive MoveAbort (code 2) in `get_auth` surfaces as a
		// build-time error rather than an executed transaction with failed
		// effects.
		await expect(sender.sweep(senderGas)).rejects.toThrow(
			/abort code: 2.*payment_channel::get_auth/,
		);
	});

	it('receiver init rejects a channel naming someone else as receiver', async () => {
		const notTheReceiver = new Receiver({
			suiClient,
			walletKeypair: senderKp,
			contraTokenAccount: senderTokenAccount,
			tokenType: deployment.buType,
			channelAddress: channelObjectId,
			contraPackageId: deployment.contra.packageId,
			paymentChannelPackageId: deployment.paymentChannel.paymentChannelPackageId,
			confidentialTokenId: deployment.confidentialTokenId,
			auditorPk: null,
			gracePeriodMs: GRACE_PERIOD_MS,
			table,
		});
		await expect(notTheReceiver.init()).rejects.toThrow(/is not this wallet/);
	});

	it('receiver init rejects a channel with too little time left to settle', async () => {
		const receiver = new Receiver({
			suiClient,
			walletKeypair: receiverKp,
			contraTokenAccount: receiverTokenAccount,
			tokenType: deployment.buType,
			channelAddress: channelObjectId,
			contraPackageId: deployment.contra.packageId,
			paymentChannelPackageId: deployment.paymentChannel.paymentChannelPackageId,
			confidentialTokenId: deployment.confidentialTokenId,
			auditorPk: null,
			gracePeriodMs: GRACE_PERIOD_MS,
			table,
		});
		// The channel was activated with a ~10 minute window; demand a day.
		await expect(receiver.init(24n * 60n * 60n * 1000n)).rejects.toThrow(/leaves less than/);
	});

	it('receiver init rejects a token whose auditor configuration differs from the pin', async () => {
		const receiver = new Receiver({
			suiClient,
			walletKeypair: receiverKp,
			contraTokenAccount: receiverTokenAccount,
			tokenType: deployment.buType,
			channelAddress: channelObjectId,
			contraPackageId: deployment.contra.packageId,
			paymentChannelPackageId: deployment.paymentChannel.paymentChannelPackageId,
			confidentialTokenId: deployment.confidentialTokenId,
			// The BU test token has auditing disabled, so pinning any key must be rejected.
			auditorPk: new Uint8Array(32).fill(1),
			gracePeriodMs: GRACE_PERIOD_MS,
			table,
		});
		await expect(receiver.init()).rejects.toThrow(/auditor/);
	});

	it('lastTimeToSettle is null while the pinned auditor configuration is unchanged', async () => {
		const receiver = await makeReceiver();
		expect(await receiver.lastTimeToSettle()).toBeNull();
	});

	it('receiver rejects a settlement whose gas budget exceeds its cap', async () => {
		const sender = makeSender();
		const receiver = await makeReceiver();
		const recvGas = await pickSuiGasCoin(suiClient, receiverKp.toSuiAddress());
		const overBudget = await sender.transfer(5n, recvGas, 500_000_000n);
		await expect(receiver.update(5n, overBudget)).rejects.toThrow(/gas budget .* exceeds cap/);
	});

	it('receiver rejects a settlement smuggling a get_auth on another channel', async () => {
		// A second channel from the same sender (Initialized is enough:
		// `get_auth` releases auth unconditionally pre-activation).
		const { channelObjectId: otherChannelId } = await createChannel({
			suiClient,
			paymentChannelClient,
			tokenType: deployment.buType,
			senderKp,
		});

		// Hand-build a settlement-shaped tx whose first command grabs auth on
		// the *other* channel before the legitimate transfer.
		const tx = new Transaction();
		tx.add(
			paymentChannelClient.getAuth({
				channel: tx.object(otherChannelId),
				tokenType: deployment.buType,
			}),
		);
		tx.add(
			await contraClient.transfer({
				tokenAccount: channelTokenAccount,
				receiverAddress: receiverKp.toSuiAddress(),
				amount: 5n,
				auth: (innerTx) =>
					innerTx.add(
						paymentChannelClient.getAuth({
							channel: innerTx.object(channelObjectId),
							tokenType: deployment.buType,
						}),
					),
				merge: false,
			}),
		);
		tx.setSender(senderKp.toSuiAddress());
		tx.setGasOwner(receiverKp.toSuiAddress());
		tx.setGasPayment([await pickSuiGasCoin(suiClient, receiverKp.toSuiAddress())]);
		tx.setGasBudget(200_000_000n);
		const txBytes = await tx.build({ client: suiClient });
		const { signature: senderSignature } = await senderKp.signTransaction(txBytes);

		const receiver = await makeReceiver();
		await expect(
			receiver.update(5n, { cumulativeAmount: 5n, txBytes, senderSignature }),
		).rejects.toThrow(/get_auth must target this channel/);
	});

	it('receiver settles, then sender sweeps the residual without waiting for end_time', async () => {
		const sender = makeSender();
		const receiver = await makeReceiver();

		const recvGas = await pickSuiGasCoin(suiClient, receiverKp.toSuiAddress());
		const t1 = await sender.transfer(20n, recvGas);
		await receiver.update(20n, t1);
		const t2 = await sender.transfer(15n, recvGas);
		await receiver.update(15n, t2);
		expect(receiver.getAccumulated()).toBe(35n);

		const settled = await receiver.settle();
		expect(settled.$kind).toBe('Transaction');
		await suiClient.core.waitForTransaction({ result: settled });
		const failed = (settled.Transaction?.events ?? []).find((e) =>
			e.eventType.includes('::events::TryTransferFailedEvent'),
		);
		expect(failed, 'channel transfer should not have hit TryTransferFailedEvent').toBeUndefined();

		const recvBal = await contraClient.getBalance(receiverTokenAccount);
		expect(recvBal.pending.amount).toBe(35n);

		// Sender, now that the channel is Closed, can sweep the residual.
		// The sweep is a plain non-sponsored tx: the sender pays gas from its
		// own coin and no gas owner is set.
		const senderGas = await pickSuiGasCoin(suiClient, senderKp.toSuiAddress());
		const sweep = await sender.sweep(senderGas);
		expect(sweep.$kind).toBe('Transaction');
		await suiClient.core.waitForTransaction({ result: sweep });
		const sweepFailed = (sweep.Transaction?.events ?? []).find((e) =>
			e.eventType.includes('::events::TryTransferFailedEvent'),
		);
		expect(sweepFailed, 'sweep should not have hit TryTransferFailedEvent').toBeUndefined();

		const senderBal = await contraClient.getBalance(senderTokenAccount);
		expect(senderBal.pending.amount).toBe(lockedAmount - 35n);
	});

	it('after end_time the sender sweeps an unsettled channel via the timeout path', async () => {
		// A fresh short-lived channel: the receiver never settles, so the
		// sender reclaims through the `clock >= end_time_ms` branch of
		// `get_auth` with a plain non-sponsored sweep.
		const { channelObjectId: shortChannelId } = await createChannel({
			suiClient,
			paymentChannelClient,
			tokenType: deployment.buType,
			senderKp,
		});
		const shortChannelTokenAccount = await setupChannelContraAccount({
			suiClient,
			contraClient,
			paymentChannelClient,
			deployment,
			senderKp,
			channelObjectId: shortChannelId,
		});
		const endTimeMs = BigInt(Date.now() + 5_000);
		await fundAndActivateChannel({
			suiClient,
			contraClient,
			paymentChannelClient,
			deployment,
			senderKp,
			channelObjectId: shortChannelId,
			receiverAddress: receiverKp.toSuiAddress(),
			endTimeMs,
			fundAmount: 10n,
		});

		// A prudent receiver would refuse this channel outright: the default
		// init margin (60s) exceeds the 5s window.
		const receiver = new Receiver({
			suiClient,
			walletKeypair: receiverKp,
			contraTokenAccount: receiverTokenAccount,
			tokenType: deployment.buType,
			channelAddress: shortChannelId,
			contraPackageId: deployment.contra.packageId,
			paymentChannelPackageId: deployment.paymentChannel.paymentChannelPackageId,
			confidentialTokenId: deployment.confidentialTokenId,
			auditorPk: null,
			gracePeriodMs: GRACE_PERIOD_MS,
			table,
		});
		await expect(receiver.init()).rejects.toThrow(/leaves less than/);

		const sender = new Sender({
			suiClient,
			contraClient,
			paymentChannelClient,
			walletKeypair: senderKp,
			tokenType: deployment.buType,
			channelObjectId: shortChannelId,
			channelTokenAccount: shortChannelTokenAccount,
			receiverAddress: receiverKp.toSuiAddress(),
			sweepDestAddress: senderTokenAccount.address,
		});

		const before = await contraClient.getBalance(senderTokenAccount);
		// Wait until the deadline has comfortably passed (devnet clock lags
		// wall time by at most a checkpoint or two).
		await new Promise((r) => setTimeout(r, 12_000));

		const senderGas = await pickSuiGasCoin(suiClient, senderKp.toSuiAddress());
		const sweep = await sender.sweep(senderGas);
		expect(sweep.$kind).toBe('Transaction');
		await suiClient.core.waitForTransaction({ result: sweep });
		const sweepFailed = (sweep.Transaction?.events ?? []).find((e) =>
			e.eventType.includes('::events::TryTransferFailedEvent'),
		);
		expect(sweepFailed, 'timeout sweep should not soft-fail').toBeUndefined();

		const after = await contraClient.getBalance(senderTokenAccount);
		expect(after.pending.amount - before.pending.amount).toBe(10n);
	});
});
