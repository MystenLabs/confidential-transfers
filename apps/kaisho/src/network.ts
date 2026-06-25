// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Single source of truth for the Sui network the demo wallet runs against.
 * Change `NETWORK` to retarget the app; every RPC client, faucet call,
 * wallet-chain guard, and explorer link is derived from it.
 */
export const NETWORK = 'testnet' as const;

export type Network = typeof NETWORK;

/** The `sui:<network>` chain identifier wallets report (e.g. `sui:testnet`). */
export const WALLET_CHAIN = `sui:${NETWORK}` as const;

/** Build a Suiscan explorer URL for the active network. */
export function explorerUrl(kind: 'tx' | 'object' | 'account', id: string): string {
	return `https://suiscan.xyz/${NETWORK}/${kind}/${id}`;
}
