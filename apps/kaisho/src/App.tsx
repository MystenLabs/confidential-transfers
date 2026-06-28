// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ConnectButton, useCurrentAccount } from '@mysten/dapp-kit';
import { useEffect, useRef } from 'react';
import { Route, Routes } from 'react-router-dom';

import { NetworkBanner } from './components/NetworkBanner';
import { NetworkPicker } from './components/NetworkPicker';
import { WalletGuard } from './components/WalletGuard';
import { Auditor } from './pages/Auditor';
import { ConfigHub } from './pages/ConfigHub';
import { Home } from './pages/Home';
import { IssuerMonitor } from './pages/IssuerMonitor';
import { Landing } from './pages/Landing';

export default function App() {
	const account = useCurrentAccount();

	// Reload on account switch so per-account in-memory state (decryption keys,
	// cached balances, react-query caches) is rebuilt against the new address.
	// Skip the initial null → account transition (first connect).
	const prevAddress = useRef<string | null>(null);
	useEffect(() => {
		const next = account?.address ?? null;
		if (prevAddress.current && next && prevAddress.current !== next) {
			window.location.reload();
			return;
		}
		prevAddress.current = next;
	}, [account?.address]);

	return (
		<div className="min-h-screen">
			{/* Animated background */}
			<div className="bg-scene" aria-hidden="true">
				<div className="bg-blob-accent" />
			</div>
			<div className="bg-grid" aria-hidden="true" />

			<header className="flex items-start justify-between px-6 py-5">
				<div className="flex flex-col gap-2">
					<div className="flex items-center gap-2.5">
						<h1 className="text-xl font-bold tracking-tight text-white">
							Kaisho{' '}
							<span className="text-sm font-medium text-zinc-500">
								(
								<span
									className="text-lg"
									style={{
										fontFamily: "'Cambria Math', 'Latin Modern Math', 'STIX Two Math', serif",
										fontStyle: 'italic',
									}}
								>
									β
								</span>
								-version)
							</span>
						</h1>
						<img src="/sui-logo.svg" alt="Sui" className="ml-1 h-6 w-6 rounded opacity-60" />
					</div>
					<NetworkPicker />
				</div>
				<ConnectButton />
			</header>

			<main className="mx-auto max-w-lg px-5 pb-16 pt-2">
				<NetworkBanner />
				<Routes>
					<Route path="/" element={<Landing />} />
					<Route path="/:configId" element={<ConfigHub />} />
					<Route path="/:configId/issuer" element={<IssuerMonitor />} />
					<Route path="/:configId/auditor" element={<Auditor />} />
					<Route
						path="/:configId/wallet"
						element={
							<WalletGuard>
								<Home />
							</WalletGuard>
						}
					/>
				</Routes>
			</main>
		</div>
	);
}
