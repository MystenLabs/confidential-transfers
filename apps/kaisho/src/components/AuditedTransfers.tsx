// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import { eventsContracts } from 'ts-sdk';
import type { ContraAuditor } from 'ts-sdk';

import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { useActivityEvents } from '../hooks/useActivityEvents';
import type { ModuleEvent } from '../hooks/useActivityEvents';
import { explorerUrl } from '../network';
import { auditTransferAmount } from '../sdk';
import type { TokenConfig } from '../sdk';

type EventKind = 'Wrap' | 'Transfer' | 'Unwrap';

interface AuditRow {
	key: string;
	kind: EventKind;
	from: string;
	to: string;
	/** Amount in raw base units; `null` when a transfer carried no auditor-readable ciphertext. */
	amount: bigint | null;
	memo: string;
	txDigest: string;
	timestampMs: number | undefined;
}

const MAX_ROWS = 20;

function relativeTime(timestampMs: number | undefined): string {
	if (!timestampMs) return '—';
	const secs = Math.floor((Date.now() - timestampMs) / 1000);
	if (secs < 60) return `${secs}s ago`;
	const mins = Math.floor(secs / 60);
	if (mins < 60) return `${mins}m ago`;
	const hours = Math.floor(mins / 60);
	if (hours < 24) return `${hours}h ago`;
	return `${Math.floor(hours / 24)}d ago`;
}

function decodeMemo(raw: number[]): string {
	if (raw.length === 0) return '';
	try {
		return new TextDecoder().decode(Uint8Array.from(raw));
	} catch {
		return '';
	}
}

/**
 * Parse a wrap / transfer / unwrap event into an audit row. Wrap and unwrap amounts are public (a
 * plaintext `u64`); transfer amounts are decrypted with the auditor key. Returns `null` for any other
 * event type.
 */
function parseAuditRow(event: ModuleEvent, auditor: ContraAuditor): AuditRow | null {
	const { txDigest, timestampMs } = event;

	if (event.eventType.includes('WrapEvent')) {
		const parsed = eventsContracts.WrapEvent.parse(event.bcs);
		return {
			key: `${txDigest}:wrap:${parsed.receiver}`,
			kind: 'Wrap',
			from: event.sender,
			to: parsed.receiver,
			amount: BigInt(parsed.amount),
			memo: decodeMemo(parsed.memo),
			txDigest,
			timestampMs,
		};
	}

	if (event.eventType.includes('UnwrapEvent')) {
		const parsed = eventsContracts.UnwrapEvent.parse(event.bcs);
		return {
			key: `${txDigest}:unwrap:${parsed.sender}`,
			kind: 'Unwrap',
			from: parsed.sender,
			to: '',
			amount: BigInt(parsed.amount),
			memo: '',
			txDigest,
			timestampMs,
		};
	}

	if (event.eventType.includes('TransferEvent')) {
		const parsed = eventsContracts.TransferEvent.parse(event.bcs);
		return {
			key: `${txDigest}:transfer:${parsed.receiver}`,
			kind: 'Transfer',
			from: parsed.sender,
			to: parsed.receiver,
			amount: auditTransferAmount(auditor, event.bcs),
			memo: decodeMemo(parsed.memo),
			txDigest,
			timestampMs,
		};
	}

	return null;
}

/**
 * Per-transfer audit panel: polls the token's on-chain events and shows the most recent wraps,
 * transfers, and unwraps. Wrap and unwrap amounts are already public; transfer amounts are decrypted
 * with the auditor key (regrouping the receiver's four u16 limbs into two u32-limb commitments and
 * pairing them with the event's two `auditor_handles`). The auditor sees each transfer's amount,
 * sender, and receiver — but never a user's viewing key or standing balance.
 */
export function AuditedTransfers({
	config,
	auditor,
}: {
	config: TokenConfig;
	auditor: ContraAuditor;
}) {
	const network = useActiveNetwork();
	const { events, isLoading } = useActivityEvents(config, true);

	const rows = useMemo(() => {
		return events
			.map((e) => {
				try {
					return parseAuditRow(e, auditor);
				} catch {
					return null;
				}
			})
			.filter((r): r is AuditRow => r !== null)
			.slice(0, MAX_ROWS);
	}, [events, auditor]);

	// Re-render relative timestamps every 10s.
	const [, setTick] = useState(0);
	useEffect(() => {
		const id = setInterval(() => setTick((t) => t + 1), 10_000);
		return () => clearInterval(id);
	}, []);

	const short = (addr: string) => (addr ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : '—');

	return (
		<div className="card flex flex-col gap-4 p-5">
			<div>
				<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
					Audited Activity
				</p>
				<p className="mt-1 text-xs text-zinc-500">
					The most recent wraps, transfers, and unwraps for this token.
				</p>
			</div>

			{isLoading && rows.length === 0 ? (
				<p className="text-xs text-zinc-500">Loading activity…</p>
			) : rows.length === 0 ? (
				<p className="text-xs text-zinc-500">No activity yet.</p>
			) : (
				<div className="overflow-hidden rounded-lg border border-white/[0.04]">
					<table className="w-full font-mono text-[11px]">
						<thead className="bg-white/[0.03] text-[10px] uppercase tracking-[0.15em] text-zinc-500">
							<tr>
								<th className="px-2.5 py-1.5 text-left font-semibold">Time</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">Type</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">From</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">To</th>
								<th className="px-2.5 py-1.5 text-right font-semibold">Amount (BU)</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">Memo</th>
								<th className="px-2.5 py-1.5 text-right font-semibold">Tx</th>
							</tr>
						</thead>
						<tbody>
							{rows.map((r) => (
								<tr key={r.key} className="border-t border-white/[0.04]">
									<td
										className="whitespace-nowrap px-2.5 py-1.5 tabular-nums text-zinc-500"
										title={r.timestampMs ? new Date(r.timestampMs).toLocaleString() : undefined}
									>
										{relativeTime(r.timestampMs)}
									</td>
									<td className="px-2.5 py-1.5 text-zinc-300">{r.kind}</td>
									<td className="px-2.5 py-1.5 text-zinc-400">{short(r.from)}</td>
									<td className="px-2.5 py-1.5 text-zinc-400">{short(r.to)}</td>
									<td className="px-2.5 py-1.5 text-right tabular-nums text-white">
										{r.amount === null ? '—' : (Number(r.amount) / 1e9).toString()}
									</td>
									<td className="px-2.5 py-1.5 text-zinc-500">{r.memo || '—'}</td>
									<td className="px-2.5 py-1.5 text-right">
										<a
											href={explorerUrl(network, 'tx', r.txDigest)}
											target="_blank"
											rel="noopener noreferrer"
											className="inline-flex opacity-50 transition-opacity hover:opacity-90"
											title="View transaction on Suiscan"
										>
											<img src="/suiscan-icon.png" alt="Suiscan" className="h-3.5 w-3.5" />
										</a>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</div>
	);
}
