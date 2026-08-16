// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Ergonomic wrapper over `sui.rpc.v2.LedgerService/ListEvents` — the indexed,
 * filtered event query that replaces JSON-RPC's `queryEvents`. The protocol
 * types and service client come from `@mysten/sui`; this module only builds
 * the DNF filter from plain terms and drains the response stream into an
 * array.
 */

import { GrpcTypes } from '@mysten/sui/grpc';
import type { SuiGrpcClient } from '@mysten/sui/grpc';

/** One conjunction of an event query: fields set on the same term are ANDed;
 *  multiple terms passed to {@link listEvents} are ORed. */
export interface EventQueryTerm {
	/** Match transactions sent by this address. */
	sender?: string;
	/** Match events emitted by calls into `package[::module]`. */
	emitModule?: string;
	/** Match events whose type is/starts at `address[::module[::Name]]`. */
	eventType?: string;
}

/** An event returned by {@link listEvents}, with its ledger position. */
export interface LedgerEvent {
	packageId: string;
	module: string;
	sender: string;
	eventType: string;
	/** Raw BCS bytes of the event struct. */
	bcs: Uint8Array;
	checkpoint: bigint | undefined;
	transactionDigest: string;
	eventIndex: number;
}

/** Fields of `sui.rpc.v2.Event` this wrapper reads. `json` is intentionally
 *  omitted — consumers parse `contents` BCS instead. */
const READ_MASK_PATHS = [
	'package_id',
	'module',
	'sender',
	'event_type',
	'contents',
	'checkpoint',
	'transaction_digest',
	'event_index',
];

function termToProto(term: EventQueryTerm): GrpcTypes.EventTerm {
	const literals: GrpcTypes.EventLiteral[] = [];
	if (term.sender !== undefined) {
		literals.push({
			negated: false,
			predicate: { oneofKind: 'sender', sender: { address: term.sender } },
		});
	}
	if (term.emitModule !== undefined) {
		literals.push({
			negated: false,
			predicate: { oneofKind: 'emitModule', emitModule: { module: term.emitModule } },
		});
	}
	if (term.eventType !== undefined) {
		literals.push({
			negated: false,
			predicate: { oneofKind: 'eventType', eventType: { eventType: term.eventType } },
		});
	}
	return { literals };
}

/**
 * Query indexed events from a fullnode, newest or oldest first. `anyOf` is a
 * DNF filter: terms are ORed, fields within one term are ANDed; omit it to
 * match every event in the checkpoint range.
 */
export async function listEvents(opts: {
	client: SuiGrpcClient;
	anyOf?: EventQueryTerm[];
	/** Maximum events to return. The server also enforces its own cap. */
	limit?: number;
	/** Newest-first when true; oldest-first (the default) otherwise. */
	descending?: boolean;
	/** Start of the checkpoint range (inclusive). Defaults to genesis. */
	startCheckpoint?: bigint;
	/** End of the checkpoint range (exclusive). Defaults to the ledger tip. */
	endCheckpoint?: bigint;
	signal?: AbortSignal;
}): Promise<LedgerEvent[]> {
	const call = opts.client.ledgerService.listEvents(
		{
			readMask: { paths: READ_MASK_PATHS },
			startCheckpoint: opts.startCheckpoint,
			endCheckpoint: opts.endCheckpoint,
			filter: opts.anyOf?.length ? { terms: opts.anyOf.map(termToProto) } : undefined,
			options: {
				limit: opts.limit,
				ordering: opts.descending ? GrpcTypes.Ordering.DESCENDING : GrpcTypes.Ordering.ASCENDING,
			},
		},
		{ abort: opts.signal },
	);

	const events: LedgerEvent[] = [];
	for await (const frame of call.responses) {
		const ev = frame.event;
		if (!ev) continue;
		events.push({
			packageId: ev.packageId ?? '',
			module: ev.module ?? '',
			sender: ev.sender ?? '',
			eventType: ev.eventType ?? '',
			bcs: ev.contents?.value ?? new Uint8Array(),
			checkpoint: ev.checkpoint,
			transactionDigest: ev.transactionDigest ?? '',
			eventIndex: ev.eventIndex ?? 0,
		});
		if (opts.limit !== undefined && events.length >= opts.limit) break;
	}
	// Surface any trailer-reported error (ignored when we broke out early).
	if (opts.limit === undefined || events.length < opts.limit) {
		await call.status;
	}
	return events;
}
