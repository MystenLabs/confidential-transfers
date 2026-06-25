// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount, useSuiClientQuery } from '@mysten/dapp-kit';
import type { SuiEvent } from '@mysten/sui/jsonRpc';
import { useEffect, useMemo, useState } from 'react';
import type { DiscreteLogTable, TokenAccount } from 'ts-sdk';

import { useDLogTable } from '../hooks/useDLogTable';
import { explorerUrl } from '../network';
import { decryptTransferEventAmount } from '../sdk';
import type { TokenConfig } from '../sdk';

interface ActivityRow {
	timestampMs: string | undefined;
	label: string;
	amount: string;
	txDigest: string;
	memo?: string;
}

function truncateAddress(addr: string): string {
	if (addr.length <= 12) return addr;
	return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function relativeTime(timestampMs: string | undefined): string {
	if (!timestampMs) return '—';
	const diff = Date.now() - Number(timestampMs);
	const secs = Math.floor(diff / 1000);
	if (secs < 60) return `${secs}s ago`;
	const mins = Math.floor(secs / 60);
	if (mins < 60) return `${mins}m ago`;
	const hours = Math.floor(mins / 60);
	if (hours < 24) return `${hours}h ago`;
	const days = Math.floor(hours / 24);
	return `${days}d ago`;
}

function decodeMemo(json: Record<string, unknown>): string | undefined {
	const raw = json.memo;
	if (!raw || !Array.isArray(raw) || raw.length === 0) return undefined;
	try {
		return new TextDecoder().decode(new Uint8Array(raw));
	} catch {
		return undefined;
	}
}

function parseEvent(
	event: SuiEvent,
	myAddress: string,
	tokenAccount: TokenAccount | undefined,
	table: DiscreteLogTable | null,
): ActivityRow | null {
	const json = event.parsedJson as Record<string, unknown>;
	const txDigest = event.id.txDigest;
	const timestampMs = event.timestampMs ?? undefined;

	if (event.type.includes('WrapEvent')) {
		const receiver = json.receiver as string;
		const txSender = event.sender;
		const amount = Number(json.amount as string) / 1e9;
		const memo = decodeMemo(json);
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

	if (event.type.includes('UnwrapEvent')) {
		const sender = json.sender as string;
		if (sender !== myAddress) return null;
		const amount = Number(json.amount as string) / 1e9;
		return { timestampMs, label: 'Unwrap', amount: `${amount} BU`, txDigest };
	}

	if (event.type.includes('TransferEvent')) {
		const sender = json.sender as string;
		const receiver = json.receiver as string;
		const memo = decodeMemo(json);
		const formatAmount = (raw: bigint | null): string =>
			raw === null ? 'encrypted' : `${Number(raw) / 1e9} BU`;
		if (sender === myAddress) {
			const decrypted =
				tokenAccount && table
					? decryptTransferEventAmount({ event, side: 'sender', tokenAccount, table })
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
					? decryptTransferEventAmount({ event, side: 'receiver', tokenAccount, table })
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

	if (event.type.includes('MintEvent')) {
		const recipient = json.recipient as string;
		if (recipient !== myAddress) return null;
		const amount = Number(json.amount as string) / 1e9;
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
	const effectiveAddress = address ?? account?.address;
	const table = useDLogTable();

	const { data: contraData, isLoading: contraLoading } = useSuiClientQuery(
		'queryEvents',
		{
			query: {
				MoveEventModule: {
					package: config.contraPackage,
					module: 'events',
				},
			},
			limit: 50,
			order: 'descending',
		},
		{ enabled: !!effectiveAddress, refetchInterval: 3_000 },
	);

	const { data: buData, isLoading: buLoading } = useSuiClientQuery(
		'queryEvents',
		{
			query: {
				MoveModule: {
					package: config.buPackage,
					module: 'bu',
				},
			},
			limit: 50,
			order: 'descending',
		},
		{ enabled: !!effectiveAddress, refetchInterval: 3_000 },
	);

	const isLoading = contraLoading || buLoading;

	const rows = useMemo(() => {
		if (!effectiveAddress) return [];
		const allEvents = [...(contraData?.data ?? []), ...(buData?.data ?? [])].sort((a, b) => {
			const ta = Number(a.timestampMs ?? 0);
			const tb = Number(b.timestampMs ?? 0);
			return tb - ta;
		});
		return allEvents
			.map((e) => parseEvent(e, effectiveAddress, tokenAccount, table))
			.filter((r): r is ActivityRow => r !== null)
			.slice(0, 20);
	}, [contraData, buData, effectiveAddress, tokenAccount, table]);

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
								href={explorerUrl('tx', row.txDigest)}
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
