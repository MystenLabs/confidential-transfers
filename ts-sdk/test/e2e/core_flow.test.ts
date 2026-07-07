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

import { bcs } from '@mysten/sui/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { deriveObjectID, normalizeStructTag } from '@mysten/sui/utils';
import { beforeAll, describe, expect, it } from 'vitest';

import { ContraAuditor } from '../../src/auditor.js';
import * as contraContracts from '../../src/contracts/contra/contra.js';
import {
	NewRegistrationEvent as NewRegistrationEventBcs,
	TransferEvent as TransferEventBcs,
} from '../../src/contracts/contra/events.js';
import { ReceiverDoesNotAcceptDepositsError } from '../../src/error.js';
import { buildKeyEncryptionOption, point } from '../../src/helpers.js';
import { KeyEncryption } from '../../src/key_encryption.js';
import { KeyConsistencyProof, scalarToLimbs } from '../../src/nizk.js';
import { G, pointFromBcs, randomScalar } from '../../src/ristretto255.js';
import type { RistrettoPoint } from '../../src/ristretto255.js';
import { TokenAccount } from '../../src/token_account.js';
import { EncryptedAmount, MultiRecipientEncryption } from '../../src/twisted_elgamal.js';
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
		const fundAndSetupTx = new Transaction();
		const [coin1] = fundAndSetupTx.splitCoins(fundAndSetupTx.gas, [FUNDING_AMOUNT]);
		const [coin2] = fundAndSetupTx.splitCoins(fundAndSetupTx.gas, [FUNDING_AMOUNT]);
		fundAndSetupTx.transferObjects([coin1], user1Address);
		fundAndSetupTx.transferObjects([coin2], user2Address);
		for (const address of [user1Address, user2Address]) {
			const account = fundAndSetupTx.add(client.contra.newAccount({ owner: address }));
			fundAndSetupTx.add(client.contra.shareAccount({ account }));
		}
		fundAndSetupTx.setSender(contraInit.address);
		await exec(fundAndSetupTx, contraInit.keypair);

		// Register both users in parallel. Each user signs their own tx since
		// register commits to the user's viewing key.
		const auditorPks = tokenIssuer.getAuditorKeys(tokenIssuer.auditorVersion).publicKeys;
		await Promise.all(
			(
				[
					[user1, user1Address, user1TokenAccount],
					[user2, user2Address, user2TokenAccount],
				] as [Ed25519Keypair, string, TokenAccount][]
			).map(async ([keypair, address, tokenAccount]) => {
				const regTx = new Transaction();
				regTx.add(await client.contra.register({ tokenAccount, auditorPublicKeys: auditorPks }));
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

	// Fund a fresh address, create+share its Account, register under the current auditor set, and
	// optionally wrap+merge a starting balance. Fresh users keep a test independent of the shared
	// user1/user2 carry-over state.
	async function setupUser(wrapAmount: bigint) {
		const keypair = Ed25519Keypair.generate();
		const address = keypair.getPublicKey().toSuiAddress();
		const tokenAccount = new TokenAccount(address, tokenIssuer.tokenType, packageConfig);

		await contraInit.fund(address, FUNDING_AMOUNT);
		const setupTx = new Transaction();
		const account = setupTx.add(client.contra.newAccount({ owner: address }));
		setupTx.add(client.contra.shareAccount({ account }));
		setupTx.setSender(address);
		await exec(setupTx, keypair);

		const auditorPks = tokenIssuer.getAuditorKeys(tokenIssuer.auditorVersion).publicKeys;
		const regTx = new Transaction();
		regTx.add(await client.contra.register({ tokenAccount, auditorPublicKeys: auditorPks }));
		regTx.setSender(address);
		await exec(regTx, keypair);

		if (wrapAmount > 0n) {
			await tokenIssuer.mint(address, wrapAmount);
			await wrapCoin(address, keypair, address, wrapAmount);
			await mergeAndUpdate(tokenAccount, keypair);
		}
		return { keypair, address, tokenAccount };
	}

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

	it(
		'getAuditors returns keys matching the on-chain auditor set',
		{ timeout: 60_000 },
		async () => {
			const auditors = await client.contra.getAuditors(tokenIssuer.tokenType);
			const expected = tokenIssuer.getAuditorKeys(tokenIssuer.auditorVersion);

			expect(auditors.version).toBe(tokenIssuer.auditorVersion);
			expect(auditors.recommendedMinVersion).toBe(0);
			expect(auditors.pks).toHaveLength(expected.publicKeys.length);
			for (let i = 0; i < expected.publicKeys.length; i++) {
				expect(auditors.pks[i].toBytes()).toEqual(expected.publicKeys[i].toBytes());
			}
		},
	);

	it(
		'register with invalid key consistency proof which is rejected on-chain',
		{ timeout: 120_000 },
		async () => {
			const user3 = Ed25519Keypair.generate();
			const user3Address = user3.getPublicKey().toSuiAddress();
			const user3TokenAccount = new TokenAccount(
				user3Address,
				tokenIssuer.tokenType,
				packageConfig,
			);

			// Fund user3 with SUI for gas.
			await contraInit.fund(user3Address, FUNDING_AMOUNT);

			// Create and share account for user3.
			const setupTx = new Transaction();
			const account = setupTx.add(client.contra.newAccount({ owner: user3Address }));
			setupTx.add(client.contra.shareAccount({ account }));
			setupTx.setSender(user3Address);
			await exec(setupTx, user3);

			// Derive the confidential token object ID (mirrors ContraClient.#getConfidentialTokenId).
			const pid = contraInit.contraPackageId;
			const normalizedType = normalizeStructTag(tokenIssuer.tokenType);
			const confidentialTokenId = deriveObjectID(
				contraInit.tokenRegistryId,
				`${pid}::contra::TokenKey<${normalizedType}>`,
				bcs.byteVector().serialize([]).toBytes(),
			);

			// Encrypt user3's key limbs correctly, but build a sigma proof with fully random
			// responses and an empty range proof — the on-chain checks reject either one.
			const limbs = scalarToLimbs(user3TokenAccount.privateKey);
			const auditorPublicKeys = tokenIssuer.getAuditorKeys(tokenIssuer.auditorVersion).publicKeys;
			const keyEncryptionCiphertexts = limbs.map((limb) =>
				MultiRecipientEncryption.encrypt(auditorPublicKeys, limb, randomScalar()),
			);

			const fakeProof = new KeyConsistencyProof(
				Array.from({ length: 8 }, () => G.multiply(randomScalar())), // a1
				Array.from({ length: 8 }, () => G.multiply(randomScalar())), // a2
				G.multiply(randomScalar()), // a3
				Array.from({ length: 8 }, () => randomScalar()), // z1
				Array.from({ length: 8 }, () => randomScalar()), // z2
			);
			const fakeKeyEncryption = new KeyEncryption(
				keyEncryptionCiphertexts,
				fakeProof,
				new Uint8Array(),
			);

			// Build the register PTB manually so we can inject the fake viewing key.
			const regTx = new Transaction();
			const auth = regTx.add(
				contraContracts.authorizeAsSender({
					package: pid,
					typeArguments: [tokenIssuer.tokenType],
					arguments: { ct: confidentialTokenId },
				}),
			);
			regTx.add(
				contraContracts.register({
					package: pid,
					typeArguments: [tokenIssuer.tokenType],
					arguments: {
						ct: confidentialTokenId,
						account: client.contra.getAccountId(user3Address),
						auth,
						pk: point(user3TokenAccount.publicKey.toBytes()),
						keyEncryption: buildKeyEncryptionOption(pid, fakeKeyEncryption),
					},
				}),
			);
			regTx.setSender(user3Address);

			await expect(exec(regTx, user3)).rejects.toThrow();
		},
	);

	it(
		'ContraAuditor recovers user privateKey and decrypts balance',
		{ timeout: 120_000 },
		async () => {
			const version = tokenIssuer.auditorVersion;
			const auditorKeys = tokenIssuer.getAuditorKeys(version);
			expect(auditorKeys.privateKeys.length).toBeGreaterThan(0);

			const auditor = new ContraAuditor({
				suiClient: contraInit.client,
				packageConfig: packageConfig,
				tokenType: tokenIssuer.tokenType,
				table: table,
				auditorKeyForVersion: new Map([
					[version, { index: 0, privateKey: auditorKeys.privateKeys[0] }],
				]),
			});

			const recovered = await auditor.getTokenAccount(user1Address);
			expect(recovered.address).toBe(user1Address);
			expect(recovered.tokenType).toBe(user1TokenAccount.tokenType);
			expect(recovered.privateKey).toBe(user1TokenAccount.privateKey);
			expect(recovered.publicKey.toBytes()).toEqual(user1TokenAccount.publicKey.toBytes());

			// Auditor sees the same balance the user does.
			const auditorView = await client.contra.getBalance(recovered);
			const userView = await client.contra.getBalance(user1TokenAccount);
			expect(auditorView.balance.amount).toBe(userView.balance.amount);
			expect(auditorView.pending.amount).toBe(userView.pending.amount);
			expect(auditorView.pendingPublicBalance).toBe(userView.pendingPublicBalance);

			// Auditor with no record for the user's version throws.
			const wrongAuditor = new ContraAuditor({
				suiClient: contraInit.client,
				packageConfig: packageConfig,
				tokenType: tokenIssuer.tokenType,
				table: table,
				auditorKeyForVersion: new Map(),
			});
			await expect(wrongAuditor.getTokenAccount(user1Address)).rejects.toThrow(
				/no record for version/,
			);

			// Auditor whose recorded index is out of range for the on-chain
			// per-limb ciphertext throws.
			const oobAuditor = new ContraAuditor({
				suiClient: contraInit.client,
				packageConfig: packageConfig,
				tokenType: tokenIssuer.tokenType,
				table: table,
				auditorKeyForVersion: new Map([
					[
						version,
						{ index: auditorKeys.privateKeys.length, privateKey: auditorKeys.privateKeys[0] },
					],
				]),
			});
			await expect(oobAuditor.getTokenAccount(user1Address)).rejects.toThrow(/out of range/);

			// --- Private transfer + decrypt TransferEvent via auditor-recovered accounts ---
			// Establish a transferable balance for user1 (mint, wrap, merge), then
			// transfer privately to user2 and capture the tx events. The auditor
			// recovers both sender and receiver TokenAccounts; the receiver decrypts
			// `encrypted_amount_receiver`, the sender recovers its own amount from the
			// same commitments via `seed_point` + `recoverSentAmount`, and both should
			// equal the original cleartext amount. State is restored at the end so the
			// next test sees the same carry-over balances it expects.
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

			const senderAccount = await auditor.getTokenAccount(user1Address);
			const receiverAccount = await auditor.getTokenAccount(user2Address);
			expect(senderAccount.privateKey).toBe(user1TokenAccount.privateKey);
			expect(receiverAccount.privateKey).toBe(user2TokenAccount.privateKey);

			// The event's `sender_pk` and `receiver_pk` should match the sender's
			// and receiver's public keys, respectively.
			expect(pointFromBcs(decodedTransfer.sender_pk).toBytes()).toEqual(
				senderAccount.publicKey.toBytes(),
			);
			expect(pointFromBcs(decodedTransfer.receiver_pk).toBytes()).toEqual(
				receiverAccount.publicKey.toBytes(),
			);

			const decryptedSender = senderAccount.recoverSentAmount(
				EncryptedAmount.fromBcs(decodedTransfer.encrypted_amount_receiver),
				pointFromBcs(decodedTransfer.seed_point),
				decodedTransfer.batch_index,
				table,
			);
			const decryptedReceiver = receiverAccount.decryptAmount(
				EncryptedAmount.fromBcs(decodedTransfer.encrypted_amount_receiver),
				table,
			);
			expect(decryptedSender).toBe(transferAmount);
			expect(decryptedReceiver).toBe(transferAmount);

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
		'ContraAuditor recovers keys across multiple auditor versions',
		{ timeout: 600_000 },
		async () => {
			// Three fresh users, each registered under a different on-chain auditor
			// version, exercise the multi-version path of `ContraAuditor`:
			//   - userA: registered when 2 auditor keys are configured (versionA)
			//   - userB: registered when auditors are empty       (versionB) -> not auditable
			//   - userC: registered when 1 auditor key is configured (versionC)
			// A single auditor instance with one entry per (auditable) version
			// should recover the private keys for userA and userC, and reject
			// userB (registered with no auditor visibility).

			// Helper: fund a fresh address, create+share its Account, and register
			// a TokenAccount under the supplied auditor public keys. Returns the
			// registration tx result so callers can inspect emitted events.
			async function setupUser(auditorPublicKeys: RistrettoPoint[]) {
				const keypair = Ed25519Keypair.generate();
				const address = keypair.getPublicKey().toSuiAddress();
				const tokenAccount = new TokenAccount(address, tokenIssuer.tokenType, packageConfig);

				const fundTx = new Transaction();
				const [coin] = fundTx.splitCoins(fundTx.gas, [FUNDING_AMOUNT]);
				fundTx.transferObjects([coin], address);
				const account = fundTx.add(client.contra.newAccount({ owner: address }));
				fundTx.add(client.contra.shareAccount({ account }));
				fundTx.setSender(contraInit.address);
				await exec(fundTx, contraInit.keypair);

				const regTx = new Transaction();
				regTx.add(await client.contra.register({ tokenAccount, auditorPublicKeys }));
				regTx.setSender(address);
				const regResult = await exec(regTx, keypair);

				return { keypair, address, tokenAccount, regResult };
			}

			// versionA: 2 auditor keys, userA registers under them.
			await tokenIssuer.rotateAuditorKeys(2);
			const versionA = tokenIssuer.auditorVersion;
			const keysA = tokenIssuer.getAuditorKeys(versionA);
			const userA = await setupUser(keysA.publicKeys);

			// versionB: empty auditor set. Wrap 10 to userA, merge into active
			// balance so userA can transfer.
			await tokenIssuer.rotateAuditorKeys(0);
			const versionB = tokenIssuer.auditorVersion;
			await tokenIssuer.mint(userA.address, 10n * ONE);
			await wrapCoin(userA.address, userA.keypair, userA.address, 10n * ONE);
			await mergeAndUpdate(userA.tokenAccount, userA.keypair);
			await expectBalance(userA.tokenAccount, {
				balance: 10n * ONE,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// userB registers under empty auditor pks at versionB.
			const userB = await setupUser([]);
			await transfer(userA.tokenAccount, userA.keypair, userB.address, 1n * ONE);

			// versionC: rotate to 1 fresh auditor key, userC registers under it.
			await tokenIssuer.rotateAuditorKeys(1);
			const versionC = tokenIssuer.auditorVersion;
			const keysC = tokenIssuer.getAuditorKeys(versionC);
			const userC = await setupUser(keysC.publicKeys);
			await transfer(userA.tokenAccount, userA.keypair, userC.address, 2n * ONE);

			// All three on-chain versions should be distinct.
			expect(new Set([versionA, versionB, versionC]).size).toBe(3);

			// Construct an auditor with one key per *auditable* version. Use
			// index 1 for versionA (it has 2 recipients) to also validate that
			// non-zero indexing into the per-limb MultiRecipientEncryption works.
			const auditor = new ContraAuditor({
				suiClient: contraInit.client,
				packageConfig: packageConfig,
				tokenType: tokenIssuer.tokenType,
				table: table,
				auditorKeyForVersion: new Map([
					[versionA, { index: 1, privateKey: keysA.privateKeys[1] }],
					[versionC, { index: 0, privateKey: keysC.privateKeys[0] }],
				]),
			});

			// userA's registration emitted a NewRegistrationEvent<T>. Recovering the
			// private key from the event payload — rather than from the on-chain
			// account state — exercises the historical-key path described in
			// `recoverPrivateKey`'s doc, and confirms the BCS schema for the event
			// matches the on-chain layout.
			const events = userA.regResult.Transaction!.events!;
			const expectedEventType = `${packageConfig.packageId}::events::NewRegistrationEvent<${tokenIssuer.tokenType}>`;
			const newRegEvent = events.find((e) => e.eventType === expectedEventType);
			expect(newRegEvent, `expected ${expectedEventType} in tx events`).toBeDefined();
			const decoded = NewRegistrationEventBcs.parse(newRegEvent!.bcs);
			expect(decoded.owner).toBe(userA.address);
			expect(decoded.verified_key_encryption.version).toBe(versionA);
			const recoveredFromEvent = auditor.recoverPrivateKey(
				{
					ciphertext: decoded.verified_key_encryption.ciphertext.map((raw) =>
						MultiRecipientEncryption.fromBcs(raw),
					),
					version: decoded.verified_key_encryption.version,
				},
				userA.tokenAccount.publicKey,
			);
			expect(recoveredFromEvent).toBe(userA.tokenAccount.privateKey);

			// userA: registered under versionA. After wrap(10), transfer(1) to B,
			// transfer(2) to C, the active balance should be 7. The auditor
			// recovers userA's private key and sees the same balance userA does.
			const recoveredA = await auditor.getTokenAccount(userA.address);
			expect(recoveredA.privateKey).toBe(userA.tokenAccount.privateKey);
			expect(recoveredA.publicKey.toBytes()).toEqual(userA.tokenAccount.publicKey.toBytes());
			const auditorViewA = await client.contra.getBalance(recoveredA);
			const userViewA = await client.contra.getBalance(userA.tokenAccount);
			expect(auditorViewA.balance.amount).toBe(7n * ONE);
			expect(auditorViewA.balance.amount).toBe(userViewA.balance.amount);
			expect(auditorViewA.pending.amount).toBe(userViewA.pending.amount);

			// userB: registered with empty auditor pks. The on-chain
			// `verified_key_encryption.ciphertext` is empty -- by design no
			// auditor can recover this user's key, regardless of which keys
			// are in the map.
			await expect(auditor.getTokenAccount(userB.address)).rejects.toThrow(
				/registered with no auditors/,
			);

			// userC: registered under versionC. Received a 2-token transfer
			// from userA into pending balance.
			const recoveredC = await auditor.getTokenAccount(userC.address);
			expect(recoveredC.privateKey).toBe(userC.tokenAccount.privateKey);
			const auditorViewC = await client.contra.getBalance(recoveredC);
			const userViewC = await client.contra.getBalance(userC.tokenAccount);
			expect(auditorViewC.pending.amount).toBe(2n * ONE);
			expect(auditorViewC.pending.amount).toBe(userViewC.pending.amount);
			expect(auditorViewC.balance.amount).toBe(userViewC.balance.amount);
		},
	);

	it(
		'rotateKeyAndUnpauseAccount: rotates key, preserves balance, and folds pending deposits',
		{ timeout: 300_000 },
		async () => {
			// Fresh user under the current auditor set. Bootstrap funding +
			// account + register, then wrap + merge so the active balance is
			// non-zero before the rotation.
			const userKp = Ed25519Keypair.generate();
			const userAddress = userKp.getPublicKey().toSuiAddress();
			const userTokenAccount = new TokenAccount(userAddress, tokenIssuer.tokenType, packageConfig);

			await contraInit.fund(userAddress, FUNDING_AMOUNT);
			const setupTx = new Transaction();
			const account = setupTx.add(client.contra.newAccount({ owner: userAddress }));
			setupTx.add(client.contra.shareAccount({ account }));
			setupTx.setSender(userAddress);
			await exec(setupTx, userKp);

			const auditorPks = tokenIssuer.getAuditorKeys(tokenIssuer.auditorVersion).publicKeys;
			const regTx = new Transaction();
			regTx.add(
				await client.contra.register({
					tokenAccount: userTokenAccount,
					auditorPublicKeys: auditorPks,
				}),
			);
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

			// --- Rotation 1: caller supplies a fresh-scalar TokenAccount ---
			const oldPrivateKey = userTokenAccount.privateKey;
			const oldPublicKeyBytes = userTokenAccount.publicKey.toBytes();

			const newTokenAccount = new TokenAccount(
				userAddress,
				userTokenAccount.tokenType,
				packageConfig,
				randomScalar(),
			);
			// rotateKeyAndUnpauseAccount pauses, merges, rekeys, and unpauses inside its own PTB,
			// so no preceding pause transaction is required.
			const rotateFn = await client.contra.rotateKeyAndUnpauseAccount({
				tokenAccount: userTokenAccount,
				newTokenAccount,
			});
			const rotateTx = new Transaction();
			rotateTx.add(rotateFn);
			rotateTx.setSender(userAddress);
			await exec(rotateTx, userKp);

			expect(newTokenAccount.privateKey).not.toBe(oldPrivateKey);
			expect(newTokenAccount.publicKey.toBytes()).not.toEqual(oldPublicKeyBytes);

			// On-chain pk now matches the new key, and getBalance with the
			// new TokenAccount recovers the original cleartext.
			const onChainPk = await client.contra.getPublicKey(userAddress, tokenIssuer.tokenType);
			expect(onChainPk.toBytes()).toEqual(newTokenAccount.publicKey.toBytes());
			await expectBalance(newTokenAccount, {
				balance: wrapAmount,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// --- Rotation 2: with a pending public deposit outstanding so
			// rotateKeyAndUnpauseAccount's inline merge runs. ---
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
			const rotateFn2 = await client.contra.rotateKeyAndUnpauseAccount({
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
				balanceUpperBound: 1,
			});

			// Sanity check: a transfer from the post-rotation account still works.
			await transfer(rotated2, userKp, user1Address, 1n * ONE);
			await expectBalance(rotated2, {
				balance: wrapAmount + extra - 1n * ONE,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// --- Recommended rotation: issuer bumps the recommended floor so every
			// existing account is flagged as needing a refresh. The chain does not
			// enforce this; wallets are expected to honor `shouldRotateKey`. ---
			expect(await client.contra.shouldRotateKey(rotated2)).toBe(false);
			await tokenIssuer.rotateAuditorKeys(1, /* bumpRecommendedMin */ true);
			expect(await client.contra.shouldRotateKey(rotated2)).toBe(true);

			// Transfers still go through on chain even when the recommendation says
			// to rotate, since the floor is advisory only.
			await transfer(rotated2, userKp, user1Address, 1n * ONE);

			// Refresh via rotateKeyAndUnpauseAccount: SDK fetches the new auditor set internally.
			const rotated3 = new TokenAccount(
				userAddress,
				rotated2.tokenType,
				packageConfig,
				randomScalar(),
			);
			const rotateFn3 = await client.contra.rotateKeyAndUnpauseAccount({
				tokenAccount: rotated2,
				newTokenAccount: rotated3,
			});
			const rotateTx3 = new Transaction();
			rotateTx3.add(rotateFn3);
			rotateTx3.setSender(userAddress);
			await exec(rotateTx3, userKp);

			expect(await client.contra.shouldRotateKey(rotated3)).toBe(false);

			// Balance survived the recommended rotation, and transfers work again.
			await expectBalance(rotated3, {
				balance: wrapAmount + extra - 2n * ONE,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});
			await transfer(rotated3, userKp, user1Address, 1n * ONE);
			await expectBalance(rotated3, {
				balance: wrapAmount + extra - 3n * ONE,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});
		},
	);

	it(
		'rotateKeyAndTransferBatch: transfers and re-keys in one transaction',
		{ timeout: 300_000 },
		async () => {
			const wrapAmount = 7n * ONE;
			const transferAmount = 2n * ONE;
			const sender = await setupUser(wrapAmount);
			const recipient = await setupUser(0n);

			await expectBalance(sender.tokenAccount, {
				balance: wrapAmount,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// Single tx: pause → merge → transfer → re-key → unpause.
			const newSender = new TokenAccount(
				sender.address,
				tokenIssuer.tokenType,
				packageConfig,
				randomScalar(),
			);
			const fn = await client.contra.rotateKeyAndTransferBatch({
				tokenAccount: sender.tokenAccount,
				newTokenAccount: newSender,
				recipients: [{ receiverAddress: recipient.address, amount: transferAmount }],
			});
			const tx = new Transaction();
			tx.add(fn);
			tx.setSender(sender.address);
			const result = await exec(tx, sender.keypair);

			// The transfer and the re-key both landed; no optimistic-failure events were emitted.
			const events = result.Transaction!.events!;
			const hasEvent = (name: string) =>
				events.some((e) => e.eventType.includes(`::events::${name}`));
			expect(hasEvent('UpdatedPublicKeyEvent')).toBe(true);
			expect(hasEvent('TransferEvent')).toBe(true);
			expect(hasEvent('TrySetPublicKeyFailedEvent')).toBe(false);
			expect(hasEvent('TryTransferFailedEvent')).toBe(false);

			// Sender re-keyed: on-chain pk is the new one (≠ old), and the new key decrypts the
			// debited balance `wrapAmount - transferAmount`.
			const onChainPk = await client.contra.getPublicKey(sender.address, tokenIssuer.tokenType);
			expect(onChainPk.toBytes()).toEqual(newSender.publicKey.toBytes());
			expect(newSender.publicKey.toBytes()).not.toEqual(sender.tokenAccount.publicKey.toBytes());
			await expectBalance(newSender, {
				balance: wrapAmount - transferAmount,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// Recipient credited (into pending, not yet merged).
			await expectBalance(recipient.tokenAccount, {
				balance: 0n,
				pending: transferAmount,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});

			// The re-keyed sender is unpaused: a transfer back to it succeeds (the SDK would throw
			// `ReceiverDoesNotAcceptDepositsError` if it were still paused) and credits its pending
			// balance under the new key.
			await transfer(recipient.tokenAccount, recipient.keypair, sender.address, transferAmount);
			const senderView = await client.contra.getBalance(newSender);
			expect(senderView.pending.amount).toBe(transferAmount);
		},
	);

	it(
		'rotateKeyAndTransferBatch: a racing deposit no-ops both steps but keeps pause+merge; retry converges',
		{ timeout: 400_000 },
		async () => {
			const wrapAmount = 7n * ONE;
			const transferAmount = 2n * ONE;
			const raceDeposit = 1n * ONE;

			const sender = await setupUser(wrapAmount);
			const recipient = await setupUser(0n);
			// Funded with two deposits' worth: one for the race injection, one to probe afterwards
			// that the sender ended up paused.
			const depositor = await setupUser(2n * raceDeposit);
			const newSender = new TokenAccount(
				sender.address,
				tokenIssuer.tokenType,
				packageConfig,
				randomScalar(),
			);

			// Build the combined call — this reads the sender balance (= wrapAmount) now.
			const fn = await client.contra.rotateKeyAndTransferBatch({
				tokenAccount: sender.tokenAccount,
				newTokenAccount: newSender,
				recipients: [{ receiverAddress: recipient.address, amount: transferAmount }],
			});

			// Inject the race: a deposit lands in the (still-accepting) sender's pending AFTER the
			// SDK read its balance but BEFORE the combined tx executes.
			await transfer(depositor.tokenAccount, depositor.keypair, sender.address, raceDeposit);

			// Execute the now-stale combined tx.
			const tx = new Transaction();
			tx.add(fn);
			tx.setSender(sender.address);
			const result = await exec(tx, sender.keypair);

			// Both optimistic steps no-op (merge folded the raced deposit, invalidating the proofs),
			// and the tx still succeeds — no abort.
			const events = result.Transaction!.events!;
			const hasEvent = (name: string) =>
				events.some((e) => e.eventType.includes(`::events::${name}`));
			expect(hasEvent('TryTransferFailedEvent')).toBe(true);
			expect(hasEvent('TrySetPublicKeyFailedEvent')).toBe(true);
			expect(hasEvent('UpdatedPublicKeyEvent')).toBe(false);
			expect(hasEvent('TransferEvent')).toBe(false);

			// Pause + merge stayed committed: the on-chain key is still the OLD one, and the OLD key
			// decrypts the merged balance `wrapAmount + raceDeposit` in active (pending cleared).
			const pkAfterRace = await client.contra.getPublicKey(sender.address, tokenIssuer.tokenType);
			expect(pkAfterRace.toBytes()).toEqual(sender.tokenAccount.publicKey.toBytes());
			const senderAfterRace = await client.contra.getBalance(sender.tokenAccount);
			expect(senderAfterRace.balance.amount).toBe(wrapAmount + raceDeposit);
			expect(senderAfterRace.pending.amount).toBe(0n);

			// The transfer no-op'd, so the recipient was not credited.
			const recipientAfterRace = await client.contra.getBalance(recipient.tokenAccount);
			expect(recipientAfterRace.pending.amount).toBe(0n);

			// The sender is now paused: a fresh deposit to it is rejected by the SDK up front.
			await expect(
				client.contra.transferBatch({
					tokenAccount: depositor.tokenAccount,
					recipients: [{ receiverAddress: sender.address, amount: raceDeposit }],
				}),
			).rejects.toThrow(ReceiverDoesNotAcceptDepositsError);

			// Retry against the now-merged balance — still under the old key, and paused so nothing
			// can race. This time the transfer + re-key both land.
			const retryFn = await client.contra.rotateKeyAndTransferBatch({
				tokenAccount: sender.tokenAccount,
				newTokenAccount: newSender,
				recipients: [{ receiverAddress: recipient.address, amount: transferAmount }],
			});
			const retryTx = new Transaction();
			retryTx.add(retryFn);
			retryTx.setSender(sender.address);
			await exec(retryTx, sender.keypair);

			const pkAfterRetry = await client.contra.getPublicKey(sender.address, tokenIssuer.tokenType);
			expect(pkAfterRetry.toBytes()).toEqual(newSender.publicKey.toBytes());
			await expectBalance(newSender, {
				balance: wrapAmount + raceDeposit - transferAmount,
				pending: 0n,
				pendingPublicBalance: 0n,
				balanceUpperBound: 1,
			});
			const recipientAfterRetry = await client.contra.getBalance(recipient.tokenAccount);
			expect(recipientAfterRetry.pending.amount).toBe(transferAmount);
		},
	);
});
