// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount, useCurrentWallet } from '@mysten/dapp-kit';
import { useEffect, useReducer } from 'react';

import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { isNetwork, saveNetwork, SUPPORTED_NETWORKS, walletChain, type Network } from '../network';

export function NetworkBanner() {
	const account = useCurrentAccount();
	const { currentWallet } = useCurrentWallet();
	const appNetwork = useActiveNetwork();
	const [, forceUpdate] = useReducer((x: number) => x + 1, 0);

	// Some wallets (e.g. Slush) fire `standard:events` `change` on a network
	// switch with just `chains`/`features` and no `accounts`. dapp-kit's
	// built-in listener only re-syncs when `accounts` is present, so the
	// cached `useCurrentAccount` stays stale. We subscribe directly and
	// force a re-render on any change so we can re-read the live wallet.
	useEffect(() => {
		const events = currentWallet?.features['standard:events'];
		if (!events) return;
		const unsub = events.on('change', () => forceUpdate());
		return unsub;
	}, [currentWallet]);

	if (!account) return null;
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
