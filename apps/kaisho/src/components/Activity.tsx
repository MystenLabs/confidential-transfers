// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount } from '@mysten/dapp-kit-react';
import { bcs } from '@mysten/sui/bcs';
import { useEffect, useMemo, useState } from 'react';
import { eventsContracts } from 'ts-sdk';
import type { DiscreteLogTable, TokenAccount } from 'ts-sdk';

import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { useActivityEvents } from '../hooks/useActivityEvents';
import type { ModuleEvent } from '../hooks/useActivityEvents';
import { useDLogTable } from '../hooks/useDLogTable';
import { explorerUrl } from '../network';
import { decryptTransferEventAmount } from '../sdk';
import type { TokenConfig } from '../sdk';

interface ActivityRow {
	timestampMs: number | undefined;
	label: string;
	amount: string;
	txDigest: string;
	memo?: string;
}

/** `bu_token::bu::MintEvent` — the BU package has no generated BCS schemas,
 *  so the layout is declared here. */
const MintEventBcs = bcs.struct('MintEvent', {
	recipient: bcs.Address,
	amount: bcs.u64(),
});

function truncateAddress(addr: string): string {
	if (addr.length <= 12) return addr;
	return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function relativeTime(timestampMs: number | undefined): string {
	if (!timestampMs) return '—';
	const diff = Date.now() - timestampMs;
	const secs = Math.floor(diff / 1000);
	if (secs < 60) return `${secs}s ago`;
	const mins = Math.floor(secs / 60);
	if (mins < 60) return `${mins}m ago`;
	const hours = Math.floor(mins / 60);
	if (hours < 24) return `${hours}h ago`;
	const days = Math.floor(hours / 24);
	return `${days}d ago`;
}

function decodeMemo(raw: number[]): string | undefined {
	if (raw.length === 0) return undefined;
	try {
		return new TextDecoder().decode(Uint8Array.from(raw));
	} catch {
		return undefined;
	}
}

function parseEvent(
	event: ModuleEvent,
	myAddress: string,
	tokenAccount: TokenAccount | undefined,
	table: DiscreteLogTable | null,
): ActivityRow | null {
	const { txDigest, timestampMs } = event;

	if (event.eventType.includes('WrapEvent')) {
		const parsed = eventsContracts.WrapEvent.parse(event.bcs);
		const receiver = parsed.receiver;
		const txSender = event.sender;
		const amount = Number(parsed.amount) / 1e9;
		const memo = decodeMemo(parsed.memo);
		if (txSender === myAddress && receiver !== myAddress) {
			return {
				timestampMs,
				label: `Wrap to ${truncateAddress(receiver)}`,
				amount: `${amount} BU`,
				txDigest,
				memo,
			};
		}
		if (receiver === myAddress) {
			return {
				timestampMs,
				label: txSender === myAddress ? 'Wrap' : `Wrap from ${truncateAddress(txSender)}`,
				amount: `${amount} BU`,
				txDigest,
				memo,
			};
		}
		return null;
	}

	if (event.eventType.includes('UnwrapEvent')) {
		const parsed = eventsContracts.UnwrapEvent.parse(event.bcs);
		if (parsed.sender !== myAddress) return null;
		const amount = Number(parsed.amount) / 1e9;
		return { timestampMs, label: 'Unwrap', amount: `${amount} BU`, txDigest };
	}

	if (event.eventType.includes('TransferEvent')) {
		const parsed = eventsContracts.TransferEvent.parse(event.bcs);
		const { sender, receiver } = parsed;
		const memo = decodeMemo(parsed.memo);
		const formatAmount = (raw: bigint | null): string =>
			raw === null ? 'encrypted' : `${Number(raw) / 1e9} BU`;
		if (sender === myAddress) {
			const decrypted =
				tokenAccount && table
					? decryptTransferEventAmount({ eventBcs: event.bcs, side: 'sender', tokenAccount, table })
					: null;
			return {
				timestampMs,
				label: `Transfer to ${truncateAddress(receiver)}`,
				amount: formatAmount(decrypted),
				txDigest,
				memo,
			};
		}
		if (receiver === myAddress) {
			const decrypted =
				tokenAccount && table
					? decryptTransferEventAmount({
							eventBcs: event.bcs,
							side: 'receiver',
							tokenAccount,
							table,
						})
					: null;
			return {
				timestampMs,
				label: `Transfer from ${truncateAddress(sender)}`,
				amount: formatAmount(decrypted),
				txDigest,
				memo,
			};
		}
		return null;
	}

	if (event.eventType.includes('MintEvent')) {
		const parsed = MintEventBcs.parse(event.bcs);
		if (parsed.recipient !== myAddress) return null;
		const amount = Number(parsed.amount) / 1e9;
		return { timestampMs, label: 'Mint', amount: `${amount} BU`, txDigest };
	}

	return null;
}

export function Activity({
	config,
	address,
	tokenAccount,
}: {
	config: TokenConfig;
	address?: string;
	tokenAccount?: TokenAccount;
}) {
	const account = useCurrentAccount();
	const network = useActiveNetwork();
	const effectiveAddress = address ?? account?.address;
	const table = useDLogTable();

	const { events, isLoading } = useActivityEvents(config, !!effectiveAddress);

	const rows = useMemo(() => {
		if (!effectiveAddress) return [];
		return events
			.map((e) => parseEvent(e, effectiveAddress, tokenAccount, table))
			.filter((r): r is ActivityRow => r !== null)
			.slice(0, 20);
	}, [events, effectiveAddress, tokenAccount, table]);

	// Re-render relative timestamps every 10s
	const [, setTick] = useState(0);
	useEffect(() => {
		const id = setInterval(() => setTick((t) => t + 1), 10_000);
		return () => clearInterval(id);
	}, []);

	return (
		<div className="card card-shimmer card-tilt overflow-hidden">
			<div className="p-5 pb-3">
				<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
					Activity
				</p>
			</div>

			{isLoading ? (
				<div className="flex flex-col gap-0">
					{[1, 2, 3].map((i) => (
						<div key={i} className="flex items-center gap-3 border-t border-white/[0.04] px-5 py-3">
							<div className="skeleton h-3 w-12" />
							<div className="skeleton h-3 flex-1" />
							<div className="skeleton h-3 w-14" />
						</div>
					))}
				</div>
			) : rows.length === 0 ? (
				<p className="px-5 pb-5 text-xs text-zinc-600">No activity yet</p>
			) : (
				<div className="flex flex-col">
					{rows.map((row, i) => (
						<div
							key={`${row.txDigest}-${i}`}
							className="group flex items-center gap-3 border-t border-white/[0.04] px-5 py-3 transition-colors hover:bg-white/[0.02]"
						>
							<p className="w-14 shrink-0 text-[10px] tabular-nums text-zinc-600">
								{relativeTime(row.timestampMs)}
							</p>
							<div className="flex-1 min-w-0">
								<p className="truncate text-xs text-zinc-300">{row.label}</p>
								{row.memo && (
									<p className="truncate text-[10px] text-zinc-600 italic">{row.memo}</p>
								)}
							</div>
							<p className="shrink-0 text-xs font-medium tabular-nums text-zinc-400">
								{row.amount}
							</p>
							<a
								href={explorerUrl(network, 'tx', row.txDigest)}
								target="_blank"
								rel="noopener noreferrer"
								className="shrink-0 opacity-40 group-hover:opacity-80 transition-opacity"
								title="View on Suiscan"
							>
								<img src="/suiscan-icon.png" alt="Suiscan" className="h-3.5 w-3.5" />
							</a>
						</div>
					))}
				</div>
			)}
		</div>
	);
}
