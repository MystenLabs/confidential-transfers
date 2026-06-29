// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Network selection for the demo wallet. Kaisho can run against either Sui
 * `devnet` (generous faucet; periodically wiped) or `testnet` (stable; strict
 * faucet). The active network is chosen at runtime — persisted here and fed to
 * dapp-kit's `SuiClientProvider` — rather than baked in at build time.
 *
 * This module is intentionally React-free; the active-network hook lives in
 * `hooks/useActiveNetwork.ts`.
 */

export type Network = 'devnet' | 'testnet';

export const SUPPORTED_NETWORKS: readonly Network[] = ['devnet', 'testnet'] as const;

/** Network used before the user picks one (and the public-demo default). */
export const DEFAULT_NETWORK: Network = 'devnet';

const NETWORK_STORAGE_KEY = 'kaisho_network';

export function isNetwork(value: unknown): value is Network {
	return value === 'devnet' || value === 'testnet';
}

/** The persisted active network, falling back to {@link DEFAULT_NETWORK}. */
export function loadNetwork(): Network {
	try {
		const stored = localStorage.getItem(NETWORK_STORAGE_KEY);
		return isNetwork(stored) ? stored : DEFAULT_NETWORK;
	} catch {
		return DEFAULT_NETWORK;
	}
}

export function saveNetwork(network: Network): void {
	try {
		localStorage.setItem(NETWORK_STORAGE_KEY, network);
	} catch {
		// best-effort; selection just won't persist across reloads
	}
}

/** The `sui:<network>` chain identifier wallets report (e.g. `sui:testnet`). */
export function walletChain(network: Network): string {
	return `sui:${network}`;
}

/** Build a Suiscan explorer URL for the given network. */
export function explorerUrl(
	network: Network,
	kind: 'tx' | 'object' | 'account',
	id: string,
): string {
	return `https://suiscan.xyz/${network}/${kind}/${id}`;
}

/**
 * Scope a localStorage base key to a network. Deployments, issuer keys, and
 * caches live on exactly one chain, so each network keeps its own state and
 * switching networks never serves another chain's stale data.
 */
export function nsKey(base: string, network: Network): string {
	return `${base}:${network}`;
}
