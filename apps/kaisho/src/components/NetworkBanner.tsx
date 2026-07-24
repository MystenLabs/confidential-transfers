// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount, useCurrentWallet } from '@mysten/dapp-kit-react';

import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { isNetwork, saveNetwork, SUPPORTED_NETWORKS, walletChain, type Network } from '../network';

export function NetworkBanner() {
	const account = useCurrentAccount();
	const currentWallet = useCurrentWallet();
	const appNetwork = useActiveNetwork();

	if (!account) return null;
	// dapp-kit rebuilds its UiWallet/UiWalletAccount snapshots on every
	// `standard:events` change, so re-reading the account from the wallet
	// picks up network switches that only update `chains`.
	const liveAccount = currentWallet?.accounts.find((a) => a.address === account.address) ?? account;
	const chains = liveAccount.chains ?? [];

	// Aligned: the wallet reports the network kaisho is talking to.
	if (chains.some((c) => c === walletChain(appNetwork))) return null;

	// The wallet may be on another network kaisho supports — offer a one-click
	// switch of the app to match it, alongside the "switch your wallet" hint.
	const walletNetwork: Network | undefined = SUPPORTED_NETWORKS.find((n) =>
		chains.some((c) => c === walletChain(n)),
	);

	const switchAppTo = (n: Network) => {
		saveNetwork(n);
		// Deployments are per-network; go home so state rebuilds on the new one.
		window.location.href = '/';
	};

	return (
		<div className="mb-4 rounded-xl border border-amber-500/30 bg-amber-500/[0.07] p-3 text-center">
			<p className="text-xs font-semibold text-amber-300">Wallet is not on Sui {appNetwork}</p>
			<p className="mt-1 text-[11px] text-amber-200/70">
				Kaisho is set to <span className="font-mono">{appNetwork}</span>. Switch the network in your
				wallet to <span className="font-mono">{appNetwork}</span>
				{walletNetwork ? ', or switch Kaisho to match your wallet:' : ' to continue.'}
			</p>
			{walletNetwork && isNetwork(walletNetwork) && (
				<button
					onClick={() => switchAppTo(walletNetwork)}
					className="mt-2 rounded-lg bg-amber-500/15 px-3 py-1.5 text-xs font-medium text-amber-200 transition-colors hover:bg-amber-500/25"
				>
					Switch Kaisho to {walletNetwork}
				</button>
			)}
		</div>
	);
}
