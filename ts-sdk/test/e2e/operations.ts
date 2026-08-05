// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared transaction helpers for the devnet e2e suite. `createOperations`
 * binds the helpers to a deployment context (`contraInit`, `tokenIssuer`,
 * `client`) and returns them as a plain bundle, so they can be used directly
 * or spread into the harness.
 *
 * These wrap the common user-facing flows (`wrapCoin`, `transfer`, `unwrap`,
 * ...) and fresh-user provisioning; the issuer/admin/permissioned flows live
 * in `token_issuer.ts`, `admin.ts`, and `gated.ts`.
 */

import type { ClientWithExtensions } from '@mysten/sui/client';
import type { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import type { ContraInitializer } from 'contra-utils/node';
import { expect } from 'vitest';

import type { ContraClient } from '../../src/client.js';
import { TokenAccount } from '../../src/token_account.js';
import type { ContraPackageConfig, TokenBalance } from '../../src/types.js';
import type { TokenIssuer } from './token_issuer.js';

/** SUI (in MIST) used to fund a fresh user for gas. */
export const FUNDING_AMOUNT = 50_000_000n;
/** One MYCOIN, 9 decimals. */
export const ONE = 1_000_000_000n;

export type ContraTestClient = ClientWithExtensions<{ contra: ContraClient }, SuiGrpcClient>;

/** Expected decrypted balance state for an account. */
export interface ExpectedBalance {
	balance: bigint;
	pending: bigint;
	pendingPublicBalance: bigint;
	balanceUpperBound: number;
}

/** An authority that can sign a transaction. */
export interface Signer {
	keypair: Ed25519Keypair;
	address: string;
}

/** A freshly-provisioned test user. */
export interface FreshUser extends Signer {
	tokenAccount: TokenAccount;
}

/**
 * Bind the shared transaction helpers to a deployment context. Returns the
 * helpers as a plain object so callers can spread or destructure them.
 */
export function createOperations(
	contraInit: ContraInitializer,
	tokenIssuer: TokenIssuer,
	client: ContraTestClient,
	packageConfig: ContraPackageConfig,
) {
	/** Sign, execute, and wait for a transaction. Throws on failure. */
	async function exec(tx: Transaction, signer: Ed25519Keypair) {
		const result = await client.core.signAndExecuteTransaction({
			transaction: tx,
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

	/** Wrap `amount` of the first MYCOIN coin owned by `owner` into `receiver`'s account. */
	async function wrapCoin(
		owner: string,
		ownerKeypair: Ed25519Keypair,
		receiver: string,
		amount: bigint,
	) {
		const coins = await contraInit.client.core.listCoins({
			owner,
			coinType: tokenIssuer.tokenType,
		});
		expect(coins.objects.length).toBeGreaterThan(0);
		const tx = new Transaction();
		const [coin] = tx.splitCoins(tx.object(coins.objects[0].objectId), [amount]);
		tx.add(await client.contra.wrap({ coin, receiver, tokenType: tokenIssuer.tokenType }));
		tx.setSender(owner);
		await exec(tx, ownerKeypair);
	}

	/** Merge pending deposits and update balance. */
	async function mergeAndUpdate(tokenAccount: TokenAccount, signer: Ed25519Keypair) {
		const fn = await client.contra.updateBalance({ tokenAccount, merge: true });
		const tx = new Transaction();
		tx.add(fn);
		tx.setSender(tokenAccount.address);
		await exec(tx, signer);
	}

	/** Transfer `amount` from sender's private balance to receiver. */
	async function transfer(
		senderTokenAccount: TokenAccount,
		signer: Ed25519Keypair,
		receiverAddress: string,
		amount: bigint,
	) {
		const fn = await client.contra.transfer({
			tokenAccount: senderTokenAccount,
			receiverAddress,
			amount,
		});
		const tx = new Transaction();
		tx.add(fn);
		tx.setSender(senderTokenAccount.address);
		await exec(tx, signer);
	}

	/** Unwrap `amount` from private balance back to a public coin. */
	async function unwrap(
		tokenAccount: TokenAccount,
		signer: Ed25519Keypair,
		amount: bigint,
		merge = false,
	) {
		const fn = await client.contra.unwrap({ tokenAccount, amount, merge });
		const tx = new Transaction();
		const coin = tx.add(fn);
		tx.transferObjects([coin], tokenAccount.address);
		tx.setSender(tokenAccount.address);
		await exec(tx, signer);
	}

	/** Poll `getBalance` until it matches `expected`, then assert each field. */
	async function expectBalance(tokenAccount: TokenAccount, expected: ExpectedBalance, retries = 5) {
		let bal: TokenBalance | undefined;
		for (let i = 0; i < retries; i++) {
			bal = await client.contra.getBalance(tokenAccount);
			if (
				bal.balance.amount === expected.balance &&
				bal.pending.amount === expected.pending &&
				bal.pendingPublicBalance === expected.pendingPublicBalance &&
				bal.balance.upperBound === expected.balanceUpperBound
			) {
				break;
			}
			await new Promise((r) => setTimeout(r, 500));
		}
		bal ??= await client.contra.getBalance(tokenAccount);
		expect(bal.balance.amount).toBe(expected.balance);
		expect(bal.pending.amount).toBe(expected.pending);
		expect(bal.pendingPublicBalance).toBe(expected.pendingPublicBalance);
		expect(bal.balance.upperBound).toBe(expected.balanceUpperBound);
	}

	/** Run multiple balance checks in parallel. */
	async function expectBalances(checks: Array<[TokenAccount, ExpectedBalance]>) {
		await Promise.all(
			checks.map(([tokenAccount, expected]) => expectBalance(tokenAccount, expected)),
		);
	}

	/**
	 * Fund `count` fresh addresses from the issuer in one PTB, then have each user create+share its
	 * own `Account` (no `TokenAccount`s yet). Account creation is restricted to the owner, so it can't
	 * be folded into the issuer tx — each user signs its own creation (run in parallel).
	 */
	async function setupFreshAccounts(count: number): Promise<FreshUser[]> {
		const users: FreshUser[] = Array.from({ length: count }, () => {
			const keypair = Ed25519Keypair.generate();
			const address = keypair.getPublicKey().toSuiAddress();
			return {
				keypair,
				address,
				tokenAccount: new TokenAccount(address, tokenIssuer.tokenType, packageConfig),
			};
		});

		const fundTx = new Transaction();
		for (const user of users) {
			const [coin] = fundTx.splitCoins(fundTx.gas, [FUNDING_AMOUNT]);
			fundTx.transferObjects([coin], user.address);
		}
		fundTx.setSender(contraInit.address);
		await exec(fundTx, contraInit.keypair);

		await Promise.all(
			users.map(async (user) => {
				const tx = new Transaction();
				const account = tx.add(
					client.contra.newAccount({ defaultPk: user.tokenAccount.publicKey }),
				);
				tx.add(client.contra.shareAccount({ account }));
				tx.setSender(user.address);
				await exec(tx, user.keypair);
			}),
		);

		return users;
	}

	/**
	 * `setupFreshAccounts` plus a registered `TokenAccount` for each. Registrations run in parallel —
	 * each is signed by its own fresh keypair, so there is no gas-coin contention. Under per-transfer
	 * auditing, registration carries no auditor data.
	 */
	async function setupFreshUsers(count: number): Promise<FreshUser[]> {
		const users = await setupFreshAccounts(count);
		await Promise.all(
			users.map(async (user) => {
				const regTx = new Transaction();
				regTx.add(await client.contra.register({ tokenAccount: user.tokenAccount }));
				regTx.setSender(user.address);
				await exec(regTx, user.keypair);
			}),
		);
		return users;
	}

	/**
	 * `setupFreshUsers` plus an active confidential balance for each: the
	 * mints are folded into one issuer-signed PTB, and the per-user
	 * wrap+merge run in parallel (each signed by its own keypair).
	 */
	async function setupFreshUsersWithBalance(amounts: bigint[]): Promise<FreshUser[]> {
		const users = await setupFreshUsers(amounts.length);
		await tokenIssuer.mintMany(
			users.map((user, i) => ({ recipient: user.address, amount: amounts[i] })),
		);
		await Promise.all(
			users.map(async (user, i) => {
				await wrapCoin(user.address, user.keypair, user.address, amounts[i]);
				await mergeAndUpdate(user.tokenAccount, user.keypair);
			}),
		);
		return users;
	}

	/** Fund a fresh address and create+share its `Account` (no `TokenAccount` yet). */
	async function setupFreshAccount(): Promise<FreshUser> {
		const [user] = await setupFreshAccounts(1);
		return user;
	}

	/** `setupFreshAccount` plus a registered `TokenAccount` under the current auditor set. */
	async function setupFreshUser(): Promise<FreshUser> {
		const [user] = await setupFreshUsers(1);
		return user;
	}

	/** `setupFreshUser` plus an active confidential balance of `amount` (mint + wrap + merge). */
	async function setupFreshUserWithBalance(amount: bigint): Promise<FreshUser> {
		const [user] = await setupFreshUsersWithBalance([amount]);
		return user;
	}

	return {
		exec,
		wrapCoin,
		mergeAndUpdate,
		transfer,
		unwrap,
		expectBalance,
		expectBalances,
		setupFreshAccount,
		setupFreshAccounts,
		setupFreshUser,
		setupFreshUsers,
		setupFreshUserWithBalance,
		setupFreshUsersWithBalance,
	};
}

/** The transaction helpers returned by `createOperations`. */
export type Operations = ReturnType<typeof createOperations>;
