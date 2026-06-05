// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Browser-safe setup helpers shared across the contra demos: SUI faucet
 * polling, account registration, and BU mint+wrap.
 */

import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { ContraClient, TokenAccount } from 'ts-sdk';
import type { ContraPackageConfig } from 'ts-sdk';

/** Poll until `address` shows a SUI coin or `timeoutMs` elapses. Throws on timeout. */
export async function waitForSui(
	suiClient: SuiJsonRpcClient,
	address: string,
	timeoutMs = 30_000,
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const { data } = await suiClient.getCoins({
			owner: address,
			coinType: '0x2::sui::SUI',
		});
		if (data.length > 0) return;
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
	suiClient: SuiJsonRpcClient,
	contraClient: ContraClient,
	packageConfig: ContraPackageConfig,
	walletKp: Ed25519Keypair,
	tokenType: string,
): Promise<TokenAccount> {
	const tokenAccount = new TokenAccount(walletKp.toSuiAddress(), tokenType, packageConfig);

	const tx = new Transaction();
	const account = tx.add(contraClient.newAccount({ owner: walletKp.toSuiAddress() }));
	tx.add(await contraClient.register({ tokenAccount, account, auditorPublicKeys: [] }));
	tx.add(contraClient.shareAccount({ account }));

	const res = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: walletKp,
		options: { showEffects: true },
	});
	if (res.effects?.status?.status !== 'success') {
		throw new Error(`createContraAccount failed: ${JSON.stringify(res.effects?.status)}`);
	}
	await suiClient.waitForTransaction({ digest: res.digest });
	return tokenAccount;
}

/**
 * Mint a fresh batch of BU via `bu::mint_10` (10 BU = 10^10 base units),
 * split `amount` base units off it, and wrap that split portion into
 * `receiverAddress`'s pending public balance. `amount` must be ≤ 10^10.
 */
export async function mintAndWrapBu(opts: {
	suiClient: SuiJsonRpcClient;
	contraClient: ContraClient;
	walletKp: Ed25519Keypair;
	receiverAddress: string;
	amount: bigint;
	buPackageId: string;
	buTreasuryId: string;
	buType: string;
}): Promise<void> {
	const {
		suiClient,
		contraClient,
		walletKp,
		receiverAddress,
		amount,
		buPackageId,
		buTreasuryId,
		buType,
	} = opts;
	const MINT_10_AMOUNT = 10_000_000_000n;
	if (amount > MINT_10_AMOUNT) {
		throw new Error(`amount ${amount} exceeds one mint_10 (${MINT_10_AMOUNT})`);
	}

	const mintTx = new Transaction();
	mintTx.moveCall({
		target: `${buPackageId}::bu::mint_10`,
		arguments: [mintTx.object(buTreasuryId)],
	});
	const mintRes = await suiClient.signAndExecuteTransaction({
		transaction: mintTx,
		signer: walletKp,
		options: { showEffects: true },
	});
	if (mintRes.effects?.status?.status !== 'success') {
		throw new Error(`mint_10 failed: ${JSON.stringify(mintRes.effects?.status)}`);
	}
	await suiClient.waitForTransaction({ digest: mintRes.digest });

	const { data } = await suiClient.getCoins({
		owner: walletKp.toSuiAddress(),
		coinType: buType,
	});
	if (data.length === 0) throw new Error('no BU coin found after mint_10');

	const wrapTx = new Transaction();
	const [split] = wrapTx.splitCoins(wrapTx.object(data[0].coinObjectId), [wrapTx.pure.u64(amount)]);
	wrapTx.add(contraClient.wrap({ coin: split, receiver: receiverAddress, tokenType: buType }));
	const wrapRes = await suiClient.signAndExecuteTransaction({
		transaction: wrapTx,
		signer: walletKp,
		options: { showEffects: true },
	});
	if (wrapRes.effects?.status?.status !== 'success') {
		throw new Error(`wrap failed: ${JSON.stringify(wrapRes.effects?.status)}`);
	}
	await suiClient.waitForTransaction({ digest: wrapRes.digest });
}
