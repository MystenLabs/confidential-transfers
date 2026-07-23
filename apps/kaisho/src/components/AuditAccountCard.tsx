// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentClient } from '@mysten/dapp-kit-react';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import type { ContraAuditor, ContraClient, TokenAccount, TokenBalance } from 'ts-sdk';

import { auditAccount } from '../sdk';
import type { TokenConfig } from '../sdk';
import { Activity } from './Activity';

/**
 * Issuer-side audit panel: enter an account address, recover that account's
 * twisted ElGamal private key via `ContraAuditor`, and display the decrypted
 * confidential balance plus the public coin balance and the Activity feed
 * scoped to that address.
 */
export function AuditAccountCard({
	config,
	contraClient,
	auditor,
}: {
	config: TokenConfig;
	contraClient: ContraClient;
	auditor: ContraAuditor;
}) {
	const tokenType = auditor.tokenType;
	const [addressInput, setAddressInput] = useState('');
	const [auditedAddress, setAuditedAddress] = useState<string | null>(null);
	const [tokenAccount, setTokenAccount] = useState<TokenAccount | null>(null);
	const [balance, setBalance] = useState<TokenBalance | null>(null);
	const [status, setStatus] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');
	const [error, setError] = useState<string>('');

	const suiClient = useCurrentClient();
	const { data: publicBalanceData } = useQuery({
		queryKey: ['audited-balance', auditedAddress, tokenType],
		enabled: !!auditedAddress,
		refetchInterval: 4_000,
		queryFn: async () =>
			(await suiClient.core.getBalance({ owner: auditedAddress!, coinType: tokenType })).balance,
	});
	const publicBalance = publicBalanceData ? Number(publicBalanceData.balance) / 1e9 : 0;

	const handleAudit = async () => {
		const address = addressInput.trim();
		if (!address) return;
		setStatus('loading');
		setError('');
		setBalance(null);
		setTokenAccount(null);
		setAuditedAddress(null);
		try {
			const { tokenAccount: recovered, balance: bal } = await auditAccount(
				auditor,
				contraClient,
				address,
			);
			setTokenAccount(recovered);
			setBalance(bal);
			setAuditedAddress(address);
			setStatus('ok');
		} catch (e) {
			setError(String(e));
			setStatus('error');
		}
	};

	return (
		<div className="card flex flex-col gap-4 p-5">
			<div>
				<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
					Audit Account
				</p>
				<p className="mt-1 text-xs text-zinc-500">
					Enter an account address to decrypt its confidential balance and recent activity.
				</p>
			</div>
			<div className="flex gap-2">
				<input
					className="input-field flex-1 font-mono text-xs"
					placeholder="Account address (0x…)"
					value={addressInput}
					onChange={(e) => setAddressInput(e.target.value)}
					onKeyDown={(e) => {
						if (e.key === 'Enter') handleAudit();
					}}
				/>
				<button
					className="btn-primary"
					disabled={!addressInput.trim() || status === 'loading'}
					onClick={handleAudit}
					title="Recover the account's viewing key from the auditor encryption and decrypt its balance"
				>
					{status === 'loading' ? 'Auditing…' : 'Audit Account'}
				</button>
			</div>
			{status === 'error' && <p className="text-[11px] text-red-400/80 break-all">{error}</p>}

			{status === 'ok' && auditedAddress && balance && (
				<div className="flex flex-col gap-4 border-t border-white/[0.04] pt-4">
					<div className="grid grid-cols-2 gap-4">
						<div>
							<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
								Public
							</p>
							<p className="mt-2 text-2xl font-bold tabular-nums tracking-tight text-white">
								{publicBalance}
							</p>
							<p className="mt-1 text-[11px] font-medium text-zinc-600">BU</p>
						</div>
						<div>
							<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
								Private
							</p>
							<p className="mt-2 text-2xl font-bold tabular-nums tracking-tight text-white">
								{Number(
									balance.balance.amount + balance.pending.amount + balance.pendingPublicBalance,
								) / 1e9}
							</p>
							<p className="mt-1 text-[11px] font-medium text-zinc-600">BU</p>
							<div className="mt-2 space-y-0.5">
								<p className="text-[10px] text-zinc-600">
									<span className="text-zinc-500">Active (encrypted)</span>{' '}
									{(Number(balance.balance.amount) / 1e9).toString()}
								</p>
								<p className="text-[10px] text-zinc-600">
									<span className="text-zinc-500">Pending (encrypted)</span>{' '}
									{(Number(balance.pending.amount) / 1e9).toString()}
								</p>
								<p className="text-[10px] text-zinc-600">
									<span className="text-zinc-500">Pending (public)</span>{' '}
									{(Number(balance.pendingPublicBalance) / 1e9).toString()}
								</p>
							</div>
						</div>
					</div>

					<Activity
						config={config}
						address={auditedAddress}
						tokenAccount={tokenAccount ?? undefined}
					/>
				</div>
			)}
		</div>
	);
}
