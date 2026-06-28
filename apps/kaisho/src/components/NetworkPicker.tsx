// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { saveNetwork, SUPPORTED_NETWORKS, type Network } from '../network';

export function NetworkPicker() {
	const network = useActiveNetwork();

	const onChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
		const next = e.target.value as Network;
		if (next === network) return;
		saveNetwork(next);
		// Deployments, issuer keys, and caches are per-network. Reset to the
		// landing page and reload so every provider, client, and cache rebuilds
		// against the newly-selected network instead of mixing chains.
		window.location.href = '/';
	};

	return (
		<label className="flex items-center gap-1.5 text-xs text-zinc-500">
			<span className="hidden sm:inline">Network</span>
			<select
				value={network}
				onChange={onChange}
				className="rounded-lg border border-white/10 bg-white/[0.04] px-2 py-1 font-mono text-xs text-zinc-300 transition-colors hover:bg-white/[0.08] focus:outline-none"
				title="Switch the Sui network kaisho runs against"
			>
				{SUPPORTED_NETWORKS.map((n) => (
					<option key={n} value={n}>
						{n}
					</option>
				))}
			</select>
		</label>
	);
}
