// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Browser-safe setup helpers shared across the contra demos: SUI faucet
 * polling and account registration.
 */

import type { ClientWithCoreApi } from '@mysten/sui/client';
import type { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { ContraClient, TokenAccount } from 'ts-sdk';
import type { ContraPackageConfig } from 'ts-sdk';

import { executeOrThrow } from './publish.js';

/** Poll until `address` shows a SUI coin or `timeoutMs` elapses. Throws on timeout. */
export async function waitForSui(
	suiClient: ClientWithCoreApi,
	address: string,
	timeoutMs = 30_000,
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const { objects } = await suiClient.core.listCoins({
			owner: address,
			coinType: '0x2::sui::SUI',
		});
		if (objects.length > 0) return;
		await new Promise((r) => setTimeout(r, 1000));
	}
	throw new Error(`timed out waiting for SUI for ${address}`);
}

/**
 * Create a contra `Account` for `walletKp`, register a `TokenAccount<T>`
 * under it, and share the account on chain. Returns the new `TokenAccount`
 * (which carries a fresh viewing key).
 */
export async function createContraAccount(
	suiClient: ClientWithCoreApi,
	contraClient: ContraClient,
	packageConfig: ContraPackageConfig,
	walletKp: Ed25519Keypair,
	tokenType: string,
): Promise<TokenAccount> {
	const tokenAccount = new TokenAccount(walletKp.toSuiAddress(), tokenType, packageConfig);

	const tx = new Transaction();
	const account = tx.add(contraClient.newAccount({ publicKey: tokenAccount.publicKey }));
	tx.add(await contraClient.register({ tokenAccount, account }));
	tx.add(contraClient.shareAccount({ account }));

	await executeOrThrow(suiClient, tx, walletKp, 'createContraAccount');
	return tokenAccount;
}
