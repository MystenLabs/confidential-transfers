// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { describe, expect, it } from 'vitest';

import { contra } from '../../src/client.js';
import { GuardianClient } from '../../src/guardian.js';
import type { TokenAccount } from '../../src/token_account.js';
import { DiscreteLogTable } from '../../src/twisted_elgamal.js';

const deployment = {
	guardianId: process.env.GUARDIAN_E2E_ID,
	guardianPackageId: process.env.GUARDIAN_E2E_PACKAGE_ID,
	contraPackageId: process.env.GUARDIAN_E2E_CONTRA_PACKAGE_ID,
	accountRegistryId: process.env.GUARDIAN_E2E_ACCOUNT_REGISTRY_ID,
	tokenRegistryId: process.env.GUARDIAN_E2E_TOKEN_REGISTRY_ID,
	tokenType: process.env.GUARDIAN_E2E_TOKEN_TYPE,
	treasuryId: process.env.GUARDIAN_E2E_TREASURY_ID,
};
const enabled = Object.values(deployment).every(Boolean);

describe.runIf(enabled)('Guardian service', () => {
	it(
		'authorizes an on-chain transfer and unwrap through the live enclave fleet',
		{ timeout: 300_000 },
		async () => {
			const client = new SuiGrpcClient({
				network: 'devnet',
				baseUrl: process.env.GUARDIAN_E2E_GRPC_URL ?? 'https://fullnode.devnet.sui.io:443',
			}).$extend(
				contra({
					packageConfig: {
						packageId: deployment.contraPackageId!,
						accountRegistryId: deployment.accountRegistryId!,
						tokenRegistryId: deployment.tokenRegistryId!,
					},
					table: DiscreteLogTable.create(16),
				}),
			);
			const guardian = new GuardianClient({
				suiClient: client,
				packageId: deployment.guardianPackageId!,
				guardianId: deployment.guardianId!,
			});
			const sender = Ed25519Keypair.generate();
			const receiver = Ed25519Keypair.generate();
			const senderAddress = sender.getPublicKey().toSuiAddress();
			const receiverAddress = receiver.getPublicKey().toSuiAddress();
			const senderAccount = client.contra.tokenAccount({
				address: senderAddress,
				tokenType: deployment.tokenType!,
			});
			const receiverAccount = client.contra.tokenAccount({
				address: receiverAddress,
				tokenType: deployment.tokenType!,
			});

			const faucet = await requestSuiFromFaucetV2({
				host: getFaucetHost('devnet'),
				recipient: senderAddress,
			});
			if (faucet.status !== 'Success' || !faucet.coins_sent?.length) {
				throw new Error(`Faucet returned no coins: ${JSON.stringify(faucet.status)}`);
			}
			await Promise.all(
				faucet.coins_sent.map(({ transferTxDigest }) =>
					client.core.waitForTransaction({ digest: transferTxDigest }),
				),
			);

			const fundReceiver = new Transaction();
			const [gas] = fundReceiver.splitCoins(fundReceiver.gas, [50_000_000n]);
			fundReceiver.transferObjects([gas], receiverAddress);
			fundReceiver.setSender(senderAddress);
			await execute(client, fundReceiver, sender);

			await Promise.all([
				createAndRegister(client, senderAccount, sender),
				createAndRegister(client, receiverAccount, receiver),
			]);

			const initialBalance = 10_000n;
			const mintAndWrap = new Transaction();
			const [coin] = mintAndWrap.moveCall({
				target: `${deployment.tokenType!.split('::', 1)[0]}::bu::mint`,
				arguments: [
					mintAndWrap.object(deployment.treasuryId!),
					mintAndWrap.pure.u64(initialBalance),
				],
			});
			mintAndWrap.add(
				await client.contra.wrap({
					coin,
					receiver: senderAddress,
					tokenType: deployment.tokenType!,
				}),
			);
			mintAndWrap.setSender(senderAddress);
			await execute(client, mintAndWrap, sender);
			await updateBalance(client, senderAccount, sender);

			const transferAmount = 3_000n;
			const transfer = new Transaction();
			transfer.add(
				await client.contra.transfer({
					tokenAccount: senderAccount,
					receiverAddress,
					amount: transferAmount,
					merge: false,
					guardian,
				}),
			);
			transfer.setSender(senderAddress);
			await execute(client, transfer, sender);
			await updateBalance(client, receiverAccount, receiver);

			const unwrapAmount = 2_000n;
			const unwrap = new Transaction();
			const publicCoin = unwrap.add(
				await client.contra.unwrap({
					tokenAccount: senderAccount,
					amount: unwrapAmount,
					merge: false,
					guardian,
				}),
			);
			unwrap.transferObjects([publicCoin], senderAddress);
			unwrap.setSender(senderAddress);
			await execute(client, unwrap, sender);

			const [senderBalance, receiverBalance] = await Promise.all([
				client.contra.getBalance(senderAccount),
				client.contra.getBalance(receiverAccount),
			]);
			expect(senderBalance.balance.amount).toBe(initialBalance - transferAmount - unwrapAmount);
			expect(senderBalance.pending.amount).toBe(0n);
			expect(receiverBalance.balance.amount).toBe(transferAmount);
			expect(receiverBalance.pending.amount).toBe(0n);
		},
	);
});

type GuardianE2eClient = SuiGrpcClient & {
	contra: ReturnType<ReturnType<typeof contra>['register']>;
};

async function execute(
	client: GuardianE2eClient,
	transaction: Transaction,
	signer: Ed25519Keypair,
) {
	const result = await client.core.signAndExecuteTransaction({
		transaction,
		signer,
		include: { effects: true, events: true },
	});
	if (result.$kind === 'FailedTransaction') {
		throw new Error(
			`Transaction failed: ${JSON.stringify(result.FailedTransaction.effects?.status)}`,
		);
	}
	await client.core.waitForTransaction({ result });
	return result;
}

async function createAndRegister(
	client: GuardianE2eClient,
	tokenAccount: TokenAccount,
	signer: Ed25519Keypair,
) {
	const account = new Transaction();
	const created = account.add(await client.contra.newAccount({ owner: tokenAccount.address }));
	account.add(await client.contra.shareAccount({ account: created }));
	account.setSender(tokenAccount.address);
	await execute(client, account, signer);

	const registration = new Transaction();
	registration.add(await client.contra.register({ tokenAccount }));
	registration.setSender(tokenAccount.address);
	await execute(client, registration, signer);
}

async function updateBalance(
	client: GuardianE2eClient,
	tokenAccount: TokenAccount,
	signer: Ed25519Keypair,
) {
	const transaction = new Transaction();
	transaction.add(await client.contra.updateBalance({ tokenAccount, merge: true }));
	transaction.setSender(tokenAccount.address);
	await execute(client, transaction, signer);
}
