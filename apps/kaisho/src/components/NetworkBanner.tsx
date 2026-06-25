// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount, useCurrentWallet } from '@mysten/dapp-kit';
import { useEffect, useReducer } from 'react';

import { NETWORK, WALLET_CHAIN } from '../network';

export function NetworkBanner() {
	const account = useCurrentAccount();
	const { currentWallet } = useCurrentWallet();
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
	const onExpectedNetwork = liveAccount.chains?.some((c) => c === WALLET_CHAIN) ?? false;
	if (onExpectedNetwork) return null;
	return (
		<div className="mb-4 rounded-xl border border-amber-500/30 bg-amber-500/[0.07] p-3 text-center">
			<p className="text-xs font-semibold text-amber-300">Wallet is not on Sui {NETWORK}</p>
			<p className="mt-1 text-[11px] text-amber-200/70">
				Kaisho is enabled only on {NETWORK}. Switch the network in your wallet to{' '}
				<span className="font-mono">{NETWORK}</span> to continue.
			</p>
		</div>
	);
}
