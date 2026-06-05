// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Link, useParams } from 'react-router-dom';

import { useTokenConfig } from '../hooks/useTokenConfig';

export function ConfigHub() {
	const { configId } = useParams<{ configId: string }>();
	const { config, isLoading, error } = useTokenConfig(configId!);

	if (isLoading) {
		return (
			<div className="card flex items-center justify-center gap-3 p-8">
				<div className="h-4 w-4 animate-spin rounded-full border-2 border-zinc-700 border-t-accent" />
				<p className="text-sm text-zinc-500">Loading token config...</p>
			</div>
		);
	}

	if (error || !config) {
		return (
			<div className="card p-6 text-center">
				<p className="text-red-400/80">
					Failed to load TokenConfig <code className="text-xs break-all">{configId}</code>
				</p>
				{error && <p className="mt-2 text-xs text-zinc-600">{String(error)}</p>}
				<Link to="/" className="btn-primary mt-4 inline-block">
					Back to Home
				</Link>
			</div>
		);
	}

	return (
		<div className="flex flex-col gap-5">
			<div className="card card-shimmer card-tilt p-6 text-center">
				<h2 className="text-lg font-bold tracking-tight text-white">Choose a Role</h2>
				<p className="mt-2 text-xs text-zinc-500 leading-relaxed">
					Each deployment can be used from three perspectives. If you just want to send and receive
					BU, choose User — Issuer and Auditor are for whoever set up the token.
				</p>
			</div>

			{/* Primary path — most people want this */}
			<div className="card glow-border p-6">
				<h3 className="text-base font-semibold text-white">For Users</h3>
				<p className="mt-2 text-xs text-zinc-500">
					Open the wallet to wrap, transfer, and unwrap confidential balances.
				</p>
				<Link
					to={`/${configId}/wallet`}
					className="btn-primary mt-4 block text-center"
					title="Open the user wallet for this deployment"
				>
					Open Wallet
				</Link>
			</div>

			{/* Advanced roles — only relevant to the token's operator */}
			<div className="flex flex-col gap-3">
				<p className="px-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-600">
					Advanced
				</p>

				<div className="card p-5">
					<h3 className="text-xs font-semibold text-zinc-300">For Issuers</h3>
					<p className="mt-1.5 text-[11px] text-zinc-500">
						Inspect deployment details and manage the token. Management actions only work in the
						same browser that created the deployment, since the issuer key is kept in local storage.
					</p>
					<Link
						to={`/${configId}/issuer`}
						className="btn-secondary mt-3 block text-center text-xs"
						title="Open the issuer view for this deployment"
					>
						Open Issuer View
					</Link>
				</div>

				<div className="card p-5">
					<h3 className="text-xs font-semibold text-zinc-300">For Auditors</h3>
					<p className="mt-1.5 text-[11px] text-zinc-500">
						Decrypt user account balances and activity using auditor keys.
					</p>
					<Link
						to={`/${configId}/auditor`}
						className="btn-secondary mt-3 block text-center text-xs"
						title="Open the auditor view for this deployment"
					>
						Open Auditor View
					</Link>
				</div>
			</div>
		</div>
	);
}
