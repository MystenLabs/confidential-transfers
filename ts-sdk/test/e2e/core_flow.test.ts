// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Core user-facing flows: wrap, merge, unwrap, transfer, batched transfer,
 * auditor recovery, and key rotation. These tests share `user1` / `user2`
 * and run sequentially, each relying on the balance state the previous one
 * left behind.
 *
 * Admin and permissioned flows live in `admin_flows.test.ts` and
 * `permissioned.test.ts`; each suite deploys its own on-chain state so the
 * files run in parallel.
 */

import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { beforeAll, describe, expect, it } from 'vitest';

import { ContraAuditor } from '../../src/auditor.js';
import { TransferEvent as TransferEventBcs } from '../../src/contracts/contra/events.js';
import { G, pointFromBcs, randomScalar } from '../../src/ristretto255.js';
import { TokenAccount } from '../../src/token_account.js';
import { EncryptedAmount } from '../../src/twisted_elgamal.js';
import { createHarness, FUNDING_AMOUNT, ONE } from './harness.js';
import type { ExpectedBalance, Harness } from './harness.js';

describe('core user flows (devnet)', () => {
	let contraInit: Harness['contraInit'];
	let tokenIssuer: Harness['tokenIssuer'];
	let client: Harness['client'];
	let packageConfig: Harness['packageConfig'];
	let table: Harness['table'];
	let exec: Harness['exec'];
	let wrapCoin: Harness['wrapCoin'];
	let mergeAndUpdate: Harness['mergeAndUpdate'];
	let transfer: Harness['transfer'];
	let unwrap: Harness['unwrap'];
	let expectBalance: Harness['expectBalance'];
	let expectBalances: Harness['expectBalances'];
	let setupFreshUsers: Harness['setupFreshUsers'];

	let user1: Ed25519Keypair;
	let user1Address: string;
	let user1TokenAccount: TokenAccount;

	let user2: Ed25519Keypair;
	let user2Address: string;
	let user2TokenAccount: TokenAccount;

	beforeAll(async () => {
		({
			contraInit,
			tokenIssuer,
			client,
			packageConfig,
			table,
			exec,
			wrapCoin,
			mergeAndUpdate,
			transfer,
			unwrap,
			expectBalance,
			expectBalances,
			setupFreshUsers,
		} = await createHarness());

		// Create user keypairs.
		user1 = Ed25519Keypair.generate();
		user1Address = user1.getPublicKey().toSuiAddress();
		user1TokenAccount = new TokenAccount(user1Address, tokenIssuer.tokenType, packageConfig);

		user2 = Ed25519Keypair.generate();
		user2Address = user2.getPublicKey().toSuiAddress();
		user2TokenAccount = new TokenAccount(user2Address, tokenIssuer.tokenType, packageConfig);

		// Single tx: fund both users and create+share their accounts. The
		// initializer's keypair is used for all three ops so they're bundled
		// together to save two round-trips.
		// Fund both users from the issuer in one tx. Account creation is restricted to the owner, so
		// each user creates, shares, and registers their own account below (signed by themselves).
		const fundTx = new Transaction();
		const [coin1] = fundTx.splitCoins(fundTx.gas, [FUNDING_AMOUNT]);
		const [coin2] = fundTx.splitCoins(fundTx.gas, [FUNDING_AMOUNT]);
		fundTx.transferObjects([coin1], user1Address);
		fundTx.transferObjects([coin2], user2Address);
		fundTx.setSender(contraInit.address);
		await exec(fundTx, contraInit.keypair);

		// Each user creates + shares + registers their own account, in parallel. Each signs their own tx.
		await Promise.all(
			(
				[
					[user1, user1Address, user1TokenAccount],
					[user2, user2Address, user2TokenAccount],
				] as [Ed25519Keypair, string, TokenAccount][]
			).map(async ([keypair, address, tokenAccount]) => {
				const regTx = new Transaction();
				const account = regTx.add(client.contra.newAccount({ owner: tokenAccount.address }));
				regTx.add(await client.contra.register({ tokenAccount, account }));
				regTx.add(client.contra.shareAccount({ account }));
				regTx.setSender(address);
				await exec(regTx, keypair);
			}),
		);

		// Verify both accounts start at zero.
		await expectBalances([
			[
				user1TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
			[
				user2TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
		]);
	}, 180_000);

	it('wrap, merge, unwrap, transfer, verify all balances', { timeout: 300_000 }, async () => {
		// --- Mint and wrap 5 to user1 ---
		await tokenIssuer.mint(user1Address, 10n * ONE);
		await wrapCoin(user1Address, user1, user1Address, 5n * ONE);

		await expectBalances([
			[
				user1TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 5n * ONE, balanceUpperBound: 1 },
			],
			[
				user2TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
		]);

		// --- Merge and update balance for user1 ---
		await mergeAndUpdate(user1TokenAccount, user1);

		await expectBalances([
			[
				user1TokenAccount,
				{ balance: 5n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
			[
				user2TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
		]);

		// --- Unwrap 4 from user1 ---
		await unwrap(user1TokenAccount, user1, 4n * ONE);

		await expectBalances([
			[
				user1TokenAccount,
				{ balance: 1n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
			[
				user2TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
		]);

		// --- Mint and wrap 1 to user2 (public deposit) ---
		await tokenIssuer.mint(user2Address, 10n * ONE);
		await wrapCoin(user2Address, user2, user2Address, 1n * ONE);

		await expectBalances([
			[
				user1TokenAccount,
				{ balance: 1n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
			[
				user2TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 1n * ONE, balanceUpperBound: 1 },
			],
		]);

		// --- Transfer 1 from user1 private to user2 ---
		await transfer(user1TokenAccount, user1, user2Address, 1n * ONE);

		await expectBalances([
			[
				user1TokenAccount,
				{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
			],
			[
				user2TokenAccount,
				{
					balance: 0n,
					pending: 1n * ONE,
					pendingPublicBalance: 1n * ONE,
					balanceUpperBound: 1,
				},
			],
		]);
	});

	it(
		'multi-operation: wraps, public sends, private transfers, full unwraps',
		{ timeout: 300_000 },
		async () => {
			// Carry-over state from previous test:
			//   A (user1): bal=0, pendBal=0, pendPub=0, ub=1
			//   B (user2): bal=0, pendBal=1, pendPub=1, ub=0

			// --- Setup: give A public coins, give B active private balance ---
			await tokenIssuer.mint(user1Address, 5n * ONE);
			await tokenIssuer.mint(user2Address, 15n * ONE);
			await wrapCoin(user2Address, user2, user2Address, 10n * ONE);
			// B merge+update: absorbs carry-over (1 encrypted + 1 public) + 10 public = 12 active
			await mergeAndUpdate(user2TokenAccount, user2);

			await expectBalances([
				[
					user1TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
				[
					user2TokenAccount,
					{
						balance: 12n * ONE,
						pending: 0n,
						pendingPublicBalance: 0n,
						balanceUpperBound: 1,
					},
				],
			]);

			// --- A wraps 3, then wraps 2 ---
			await wrapCoin(user1Address, user1, user1Address, 3n * ONE);
			await wrapCoin(user1Address, user1, user1Address, 2n * ONE);

			await expectBalances([
				[
					user1TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 5n * ONE, balanceUpperBound: 1 },
				],
				[
					user2TokenAccount,
					{
						balance: 12n * ONE,
						pending: 0n,
						pendingPublicBalance: 0n,
						balanceUpperBound: 1,
					},
				],
			]);

			// --- B sends 2 from public balance to A (wrap to A) ---
			await wrapCoin(user2Address, user2, user1Address, 2n * ONE);

			await expectBalances([
				[
					user1TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 7n * ONE, balanceUpperBound: 1 },
				],
				[
					user2TokenAccount,
					{
						balance: 12n * ONE,
						pending: 0n,
						pendingPublicBalance: 0n,
						balanceUpperBound: 1,
					},
				],
			]);

			// --- B sends 3 from private balance to A ---
			await transfer(user2TokenAccount, user2, user1Address, 3n * ONE);

			await expectBalances([
				[
					user1TokenAccount,
					{
						balance: 0n,
						pending: 3n * ONE,
						pendingPublicBalance: 7n * ONE,
						balanceUpperBound: 1,
					},
				],
				[
					user2TokenAccount,
					{ balance: 9n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
			]);

			// --- B unwraps 3 ---
			await unwrap(user2TokenAccount, user2, 3n * ONE);

			await expectBalances([
				[
					user1TokenAccount,
					{
						balance: 0n,
						pending: 3n * ONE,
						pendingPublicBalance: 7n * ONE,
						balanceUpperBound: 1,
					},
				],
				[
					user2TokenAccount,
					{ balance: 6n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
			]);

			// --- B sends 2 from private balance to A ---
			await transfer(user2TokenAccount, user2, user1Address, 2n * ONE);

			await expectBalances([
				[
					user1TokenAccount,
					{
						balance: 0n,
						pending: 5n * ONE,
						pendingPublicBalance: 7n * ONE,
						balanceUpperBound: 1,
					},
				],
				[
					user2TokenAccount,
					{ balance: 4n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
			]);

			// --- B unwraps its entire private balance (4) ---
			await unwrap(user2TokenAccount, user2, 4n * ONE);

			await expectBalances([
				[
					user1TokenAccount,
					{
						balance: 0n,
						pending: 5n * ONE,
						pendingPublicBalance: 7n * ONE,
						balanceUpperBound: 1,
					},
				],
				[
					user2TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
			]);

			// --- A unwraps its entire private balance (merge pending first: 5+7=12) ---
			await unwrap(user1TokenAccount, user1, 12n * ONE, /* merge */ true);

			await expectBalances([
				[
					user1TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
				[
					user2TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
			]);
		},
	);

	it('getAuditor returns the current on-chain auditor keys', { timeout: 60_000 }, async () => {
		const auditor = await client.contra.getAuditor(tokenIssuer.tokenType);
		expect(auditor.currentPks).toHaveLength(1);
		expect(auditor.currentPks[0].toBytes()).toEqual(tokenIssuer.auditorPublicKey!.toBytes());
	});

	it(
		'ContraAuditor decrypts a transfer amount from the TransferEvent',
		{ timeout: 120_000 },
		async () => {
			// Per-transfer auditing: the auditor never recovers a user key. It decrypts each transfer's
			// amount from the `TransferEvent` (`encrypted_amount_receiver` + `auditor_decryption_handles`) with the
			// token's auditor private key. The sender still recovers its own outgoing amount from the
			// commitments via `seed_point`, and the receiver decrypts with its own key.
			const auditor = new ContraAuditor({
				tokenType: tokenIssuer.tokenType,
				privateKeys: [tokenIssuer.auditorPrivateKey!],
				table,
			});

			const wrapAmount = 5n * ONE;
			const transferAmount = 3n * ONE;
			await tokenIssuer.mint(user1Address, wrapAmount);
			await wrapCoin(user1Address, user1, user1Address, wrapAmount);
			await mergeAndUpdate(user1TokenAccount, user1);

			const transferFn = await client.contra.transfer({
				tokenAccount: user1TokenAccount,
				receiverAddress: user2Address,
				amount: transferAmount,
			});
			const transferTx = new Transaction();
			transferTx.add(transferFn);
			transferTx.setSender(user1Address);
			const transferResult = await exec(transferTx, user1);

			const transferEventType = `${packageConfig.packageId}::events::TransferEvent<${tokenIssuer.tokenType}>`;
			const transferEvent = transferResult.Transaction!.events!.find(
				(e) => e.eventType === transferEventType,
			);
			expect(transferEvent, `expected ${transferEventType} in tx events`).toBeDefined();
			const decodedTransfer = TransferEventBcs.parse(transferEvent!.bcs);
			expect(decodedTransfer.sender).toBe(user1Address);
			expect(decodedTransfer.receiver).toBe(user2Address);
			// The auditor's two u32-limb handles, tagged by `auditor_pk` (set here, one auditor).
			expect(decodedTransfer.auditor_pk).not.toBeNull();
			expect(decodedTransfer.auditor_decryption_handles).toHaveLength(2);

			// The event carries the amount as the receiver's four u16-limb ciphertexts.
			const receiverAmount = EncryptedAmount.fromBcs(decodedTransfer.encrypted_amount_receiver);
			const receiverLimbs = [
				receiverAmount.l0,
				receiverAmount.l1,
				receiverAmount.l2,
				receiverAmount.l3,
			];

			// Auditor recovers the amount straight from the event, matching its key to `auditor_pk`.
			const auditorAmount = auditor.decryptTransferAmount(decodedTransfer);
			expect(auditorAmount).toBe(transferAmount);

			// Sender and receiver recover the same amount their own ways.
			const decryptedSender = user1TokenAccount.recoverSentAmount(
				receiverLimbs,
				pointFromBcs(decodedTransfer.seed_point),
				decodedTransfer.batch_index,
				table,
			);
			const decryptedReceiver = user2TokenAccount.decryptAmount(receiverLimbs, table);
			expect(decryptedSender).toBe(transferAmount);
			expect(decryptedReceiver).toBe(transferAmount);

			// An auditor without the transfer's key can't decrypt it (no key matches `auditor_pk`).
			const wrongAuditor = new ContraAuditor({
				tokenType: tokenIssuer.tokenType,
				privateKeys: [randomScalar()],
				table,
			});
			let wrong: bigint | null | undefined;
			try {
				wrong = wrongAuditor.decryptTransferAmount(decodedTransfer);
			} catch {
				wrong = undefined;
			}
			expect(wrong).not.toBe(transferAmount);

			// Restore carry-over state expected by the next test:
			// both users back to balance=0, pending=0, pendingPublicBalance=0.
			await unwrap(user1TokenAccount, user1, wrapAmount - transferAmount);
			await mergeAndUpdate(user2TokenAccount, user2);
			await unwrap(user2TokenAccount, user2, transferAmount);

			await expectBalances([
				[
					user1TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
				[
					user2TokenAccount,
					{ balance: 0n, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
			]);
		},
	);

	it(
		'transfer with merge=true prepends merge_deposits in same PTB',
		{ timeout: 300_000 },
		async () => {
			// Carry-over state from previous test:
			//   A (user1): bal=0, pendBal=0, pendPub=0, ub=1
			//   B (user2): bal=0, pendBal=0, pendPub=0, ub=1
			//
			// Exercises the combined merge+transfer PTB path in client.contra.transfer:
			// when merge=true (default) AND sender has pending deposits, the SDK
			// prepends merge_deposits_to_balance so the transfer draws from
			// just-deposited funds.

			// Mint and wrap 5 to user1 -> pending public, no active balance
			await tokenIssuer.mint(user1Address, 5n * ONE);
			await wrapCoin(user1Address, user1, user1Address, 5n * ONE);

			await expectBalance(user1TokenAccount, {
				balance: 0n,
				pending: 0n,
				pendingPublicBalance: 5n * ONE,
				balanceUpperBound: 1,
			});

			// Transfer 2 to user2. user1.balance is 0 but pendingPublicBalance=5,
			// so hasPendingDeposits is true -> merge branch fires in the same PTB.
			await transfer(user1TokenAccount, user1, user2Address, 2n * ONE);

			await expectBalances([
				[
					user1TokenAccount,
					{ balance: 3n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
				[
					user2TokenAccount,
					{ balance: 0n, pending: 2n * ONE, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
			]);
		},
	);

	it(
		'transferBatch: split a single send across multiple receivers',
		{ timeout: 600_000 },
		async () => {
			// Carry-over state from previous test:
			//   user1: bal=3*ONE, pendBal=0, pendPub=0, balance.ub=1
			//   user2: bal=0,     pendBal=2*ONE, pendPub=0, balance.ub=1
			//
			// Exercises `transferBatch` with 11 receivers in one PTB — above the old
			// 7-recipient cap — so the emitted batch indices run past 7 and the
			// aggregate range proof spans more than one Bulletproof chunk.

			// Register 10 fresh receivers under the current auditor set. Together with
			// user2 the batch fans out to 11 recipients.
			const freshReceivers = await setupFreshUsers(10);

			// Top up user1's gas: the 11-recipient batch is a large PTB and user1's
			// funding has been drawn down by the earlier sequential tests.
			await contraInit.fund(user1Address, FUNDING_AMOUNT);

			// user1 sends 1*ONE to user2 and SHARE (= ONE/10) to each fresh receiver,
			// for a 2*ONE total across 11 recipients. Input order fixes each receiver's
			// batch index: user2 -> 0, freshReceivers[i] -> i + 1.
			const SHARE = ONE / 10n;
			const fn = await client.contra.transferBatch({
				tokenAccount: user1TokenAccount,
				recipients: [
					{ receiverAddress: user2Address, amount: 1n * ONE, memo: 'memo-a' },
					...freshReceivers.map((r) => ({ receiverAddress: r.address, amount: SHARE })),
				],
			});
			const tx = new Transaction();
			tx.add(fn);
			tx.setSender(user1Address);
			const result = await exec(tx, user1);

			// One TransferEvent per recipient in input order, each carrying its
			// sequential `batch_index` — the u8 index the widened cap relies on.
			const transferEventType = `${packageConfig.packageId}::events::TransferEvent<${tokenIssuer.tokenType}>`;
			const transferEvents = result.Transaction!.events!.filter(
				(e) => e.eventType === transferEventType,
			);
			expect(transferEvents.length).toBe(11);
			const decoded = transferEvents.map((e) => TransferEventBcs.parse(e.bcs));
			const expectedReceivers = [user2Address, ...freshReceivers.map((r) => r.address)];
			decoded.forEach((event, i) => {
				expect(event.sender).toBe(user1Address);
				expect(event.receiver).toBe(expectedReceivers[i]);
				expect(event.batch_index).toBe(i);
			});

			// `add_to_batch` only mutates each receiver's `pending_deposits`, never
			// `balance`: user2 keeps its carry-over balance.upperBound (1) and each
			// freshly-registered receiver stays at upperBound 1. user1's balance is set
			// via `try_update_balance` -> upperBound = 1, ending at
			// 3*ONE - 1*ONE - 10*SHARE = 1*ONE.
			await expectBalances([
				[
					user1TokenAccount,
					{ balance: 1n * ONE, pending: 0n, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
				[
					user2TokenAccount,
					{ balance: 0n, pending: 3n * ONE, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				],
				...freshReceivers.map((r): [TokenAccount, ExpectedBalance] => [
					r.tokenAccount,
					{ balance: 0n, pending: SHARE, pendingPublicBalance: 0n, balanceUpperBound: 1 },
				]),
			]);
		},
	);

	it(
		'tryRekeyTokenAccount: re-keys the token, preserving balance and folding pending deposits',
		{ timeout: 300_000 },
		async () => {
			// Fresh user. Bootstrap funding + account + register, then wrap + merge so the active
			// balance is non-zero before the rotation.
			const userKp = Ed25519Keypair.generate();
			const userAddress = userKp.getPublicKey().toSuiAddress();
			const userTokenAccount = new TokenAccount(userAddress, tokenIssuer.tokenType, packageConfig);

			await contraInit.fund(userAddress, FUNDING_AMOUNT);
			const setupTx = new Transaction();
			const account = setupTx.add(client.contra.newAccount({ owner: userTokenAccount.address }));
			setupTx.add(client.contra.shareAccount({ account }));
			setupTx.setSender(userAddress);
			await exec(setupTx, userKp);

			const regTx = new Transaction();
			regTx.add(await client.contra.register({ tokenAccount: userTokenAccount }));
			regTx.setSender(userAddress);
			await exec(regTx, userKp);

			const wrapAmount = 7n * ONE;
			await tokenIssuer.mint(userAddress, wrapAmount);
			await wrapCoin(userAddress, userKp, userAddress, wrapAmount);
			await mergeAndUpdate(userTokenAccount, userKp);

			await expectBalance(userTokenAccount, {
				balance: wrapAmount,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// --- Rotation 1: no pending deposits. `tryRekeyTokenAccount` re-keys the token in one PTB
			// (try_rekey_token_account catches the token up to the new key). ---
			const oldPrivateKey = userTokenAccount.privateKey;
			const oldPublicKeyBytes = userTokenAccount.publicKey.toBytes();

			const newTokenAccount = new TokenAccount(
				userAddress,
				userTokenAccount.tokenType,
				packageConfig,
				randomScalar(),
			);
			const rotateFn = await client.contra.tryRekeyTokenAccount({
				tokenAccount: userTokenAccount,
				newTokenAccount,
			});
			const rotateTx = new Transaction();
			rotateTx.add(rotateFn);
			rotateTx.setSender(userAddress);
			await exec(rotateTx, userKp);

			expect(newTokenAccount.privateKey).not.toBe(oldPrivateKey);
			expect(newTokenAccount.publicKey.toBytes()).not.toEqual(oldPublicKeyBytes);

			// On-chain the token is now keyed under the new key, and getBalance with the new
			// TokenAccount recovers the original cleartext.
			const onChainPk = await client.contra.getPublicKey(userAddress, tokenIssuer.tokenType);
			expect(onChainPk.toBytes()).toEqual(newTokenAccount.publicKey.toBytes());
			await expectBalance(newTokenAccount, {
				balance: wrapAmount,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// --- Rotation 2: with a pending public deposit outstanding so `tryRekeyTokenAccount`'s inline merge
			// runs (rekey_token_account requires an empty pending). ---
			const extra = 3n * ONE;
			await tokenIssuer.mint(userAddress, extra);
			await wrapCoin(userAddress, userKp, userAddress, extra);

			await expectBalance(newTokenAccount, {
				balance: wrapAmount,
				pending: 0n,
				pendingPublicBalance: extra,
				balanceUpperBound: 1,
			});

			const rotated2 = new TokenAccount(
				userAddress,
				newTokenAccount.tokenType,
				packageConfig,
				randomScalar(),
			);
			const rotateFn2 = await client.contra.tryRekeyTokenAccount({
				tokenAccount: newTokenAccount,
				newTokenAccount: rotated2,
			});
			const rotateTx2 = new Transaction();
			rotateTx2.add(rotateFn2);
			rotateTx2.setSender(userAddress);
			await exec(rotateTx2, userKp);

			expect(rotated2.privateKey).not.toBe(newTokenAccount.privateKey);
			expect(rotated2.publicKey.toBytes()).toEqual(G.multiply(rotated2.privateKey).toBytes());
			await expectBalance(rotated2, {
				balance: wrapAmount + extra,
				pending: 0n,
				pendingPublicBalance: 0n,
				// The inline merge folded the pending public deposit into `active` (bound 1 -> 2), and
				// the lazy re-key only swaps handles (preserving the bound), so this is 2, not 1.
				balanceUpperBound: 2,
			});

			// Sanity check: a transfer from the post-rotation account still works.
			await transfer(rotated2, userKp, user1Address, 1n * ONE);
			await expectBalance(rotated2, {
				balance: wrapAmount + extra - 1n * ONE,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});
		},
	);
});
