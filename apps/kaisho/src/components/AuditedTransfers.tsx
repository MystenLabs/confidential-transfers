// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from 'react';
import { TransferEventBcs } from 'ts-sdk';
import type { ContraAuditor } from 'ts-sdk';

import { useActivityEvents } from '../hooks/useActivityEvents';
import { auditTransferAmount } from '../sdk';
import type { TokenConfig } from '../sdk';

/**
 * Per-transfer audit panel: polls the token's on-chain `TransferEvent`s and, for each, decrypts the
 * amount with the auditor key (regrouping the receiver's four u16 limbs into two u32-limb
 * commitments and pairing them with the event's two `auditor_handles`). The auditor sees each
 * transfer's amount, sender, and receiver — but never a user's viewing key or standing balance.
 */
export function AuditedTransfers({
	config,
	auditor,
}: {
	config: TokenConfig;
	auditor: ContraAuditor;
}) {
	const { events, isLoading } = useActivityEvents(config, true);
	const transferPrefix = `${config.contraPackage}::events::TransferEvent`;

	const rows = useMemo(() => {
		return events
			.filter((e) => e.eventType.startsWith(transferPrefix))
			.map((e) => {
				let sender = '';
				let receiver = '';
				let memo = '';
				try {
					const decoded = TransferEventBcs.parse(e.bcs);
					sender = decoded.sender;
					receiver = decoded.receiver;
					memo = decoded.memo.length
						? new TextDecoder().decode(Uint8Array.from(decoded.memo))
						: '';
				} catch {
					/* leave fields blank; amount decrypt below still handles bad payloads */
				}
				const amount = auditTransferAmount(auditor, e.bcs);
				return {
					key: `${e.txDigest}:${receiver}`,
					sender,
					receiver,
					memo,
					amount,
					timestampMs: e.timestampMs,
				};
			});
	}, [events, auditor, transferPrefix]);

	const short = (addr: string) => (addr ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : '—');

	return (
		<div className="card flex flex-col gap-4 p-5">
			<div>
				<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
					Audited Transfers
				</p>
				<p className="mt-1 text-xs text-zinc-500">
					Every confidential transfer, with its amount decrypted from the on-chain event using the
					auditor key.
				</p>
			</div>

			{isLoading && rows.length === 0 ? (
				<p className="text-xs text-zinc-500">Loading transfers…</p>
			) : rows.length === 0 ? (
				<p className="text-xs text-zinc-500">No transfers yet.</p>
			) : (
				<div className="overflow-hidden rounded-lg border border-white/[0.04]">
					<table className="w-full font-mono text-[11px]">
						<thead className="bg-white/[0.03] text-[10px] uppercase tracking-[0.15em] text-zinc-500">
							<tr>
								<th className="px-2.5 py-1.5 text-left font-semibold">From</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">To</th>
								<th className="px-2.5 py-1.5 text-right font-semibold">Amount (BU)</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">Memo</th>
							</tr>
						</thead>
						<tbody>
							{rows.map((r) => (
								<tr key={r.key} className="border-t border-white/[0.04]">
									<td className="px-2.5 py-1.5 text-zinc-400">{short(r.sender)}</td>
									<td className="px-2.5 py-1.5 text-zinc-400">{short(r.receiver)}</td>
									<td className="px-2.5 py-1.5 text-right tabular-nums text-white">
										{r.amount === null ? '—' : (Number(r.amount) / 1e9).toString()}
									</td>
									<td className="px-2.5 py-1.5 text-zinc-500">{r.memo || '—'}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</div>
	);
}
