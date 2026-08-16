// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * On-chain event feed over gRPC, polled via `LedgerService.ListEvents` —
 * the indexed event query that replaces JSON-RPC's `queryEvents`.
 * Event timestamps are resolved from their containing checkpoints and
 * cached, since `Event` carries a checkpoint number but no timestamp.
 */

import { useCurrentClient } from '@mysten/dapp-kit-react';
import { useEffect, useRef, useState } from 'react';

import { listEvents } from '../grpc/listEvents';
import type { TokenConfig } from '../sdk';

export interface ModuleEvent {
	packageId: string;
	module: string;
	eventType: string;
	/** Address that sent the transaction that emitted the event. */
	sender: string;
	/** Raw BCS bytes of the event struct. */
	bcs: Uint8Array;
	txDigest: string;
	timestampMs: number | undefined;
}

const POLL_MS = 3_000;
const MAX_EVENTS = 50;

/**
 * The newest events relevant to the kaisho activity feed for `config`:
 *  - events declared in the contra package's `events` module (matched by
 *    event type, like the old `MoveEventModule` filter), and
 *  - events emitted by transactions calling the BU package's `bu` module
 *    (like the old `MoveModule` filter, e.g. `MintEvent`).
 */
export function useActivityEvents(config: TokenConfig, enabled: boolean) {
	const client = useCurrentClient();
	const [events, setEvents] = useState<ModuleEvent[]>([]);
	const [isLoading, setIsLoading] = useState(true);
	const timestampByCheckpointRef = useRef<Map<bigint, number>>(new Map());

	const contraPackage = config.contraPackage;
	const buPackage = config.buPackage;

	useEffect(() => {
		if (!enabled) return;
		let cancelled = false;
		setEvents([]);
		setIsLoading(true);

		const timestampFor = async (checkpoint: bigint): Promise<number | undefined> => {
			const cache = timestampByCheckpointRef.current;
			const cached = cache.get(checkpoint);
			if (cached !== undefined) return cached;
			const { response } = await client.ledgerService.getCheckpoint({
				checkpointId: { oneofKind: 'sequenceNumber', sequenceNumber: checkpoint },
				readMask: { paths: ['sequence_number', 'summary.timestamp'] },
			});
			const ts = response.checkpoint?.summary?.timestamp;
			if (ts?.seconds === undefined) return undefined;
			const ms = Number(ts.seconds) * 1000 + Math.floor((ts.nanos ?? 0) / 1e6);
			cache.set(checkpoint, ms);
			return ms;
		};

		const poll = async () => {
			try {
				const raw = await listEvents({
					client,
					anyOf: [{ eventType: `${contraPackage}::events` }, { emitModule: `${buPackage}::bu` }],
					limit: MAX_EVENTS,
					descending: true,
				});
				if (cancelled) return;
				const next = await Promise.all(
					raw.map(async (ev) => ({
						packageId: ev.packageId,
						module: ev.module,
						eventType: ev.eventType,
						sender: ev.sender,
						bcs: ev.bcs,
						txDigest: ev.transactionDigest,
						timestampMs:
							ev.checkpoint !== undefined ? await timestampFor(ev.checkpoint) : undefined,
					})),
				);
				if (cancelled) return;
				setEvents(next);
				setIsLoading(false);
			} catch (e) {
				console.warn('[useActivityEvents] poll failed', e);
			}
		};

		poll();
		const interval = setInterval(poll, POLL_MS);
		return () => {
			cancelled = true;
			clearInterval(interval);
		};
	}, [client, enabled, contraPackage, buPackage]);

	return { events, isLoading };
}
