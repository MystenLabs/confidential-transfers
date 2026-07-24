// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Client for `sui.rpc.v2.LedgerService/ListEvents` — the indexed, filtered
 * event query that replaces JSON-RPC's `queryEvents`. Fullnodes already
 * serve it, but `@mysten/sui`'s generated stubs don't cover it yet (as of
 * 2.22.x), so the messages are hand-written here from the proto source
 * (MystenLabs/sui-apis `proto/sui/rpc/v2/{ledger_service,filter,query_options}.proto`).
 * TODO: delete this file and use the SDK's generated client once it ships.
 */

import { GrpcWebFetchTransport } from '@mysten/sui/grpc';
import type { RpcTransport } from '@mysten/sui/grpc';
import { MessageType, ScalarType } from '@protobuf-ts/runtime';
import { ServiceType, stackIntercept } from '@protobuf-ts/runtime-rpc';
import { grpcUrlFor } from 'contra-utils';

import type { Network } from '../network';

// ── Proto messages (binary layout only — JSON never used) ────────────

interface FieldMask {
	paths: string[];
}
const FieldMaskMsg = new MessageType<FieldMask>('google.protobuf.FieldMask', [
	{ no: 1, name: 'paths', kind: 'scalar', repeat: 2, T: ScalarType.STRING },
]);

interface Bcs {
	name?: string;
	value?: Uint8Array;
}
const BcsMsg = new MessageType<Bcs>('sui.rpc.v2.Bcs', [
	{ no: 1, name: 'name', kind: 'scalar', T: ScalarType.STRING, opt: true },
	{ no: 2, name: 'value', kind: 'scalar', T: ScalarType.BYTES, opt: true },
]);

/** `sui.rpc.v2.Event` including the ledger-position fields (7–10) that the
 *  SDK's generated `Event` doesn't carry yet. The `json` field (6) is
 *  intentionally omitted — consumers parse `contents` BCS instead. */
interface EventProto {
	packageId?: string;
	module?: string;
	sender?: string;
	eventType?: string;
	contents?: Bcs;
	checkpoint?: bigint;
	transactionDigest?: string;
	eventIndex?: number;
}
const EventMsg = new MessageType<EventProto>('sui.rpc.v2.Event', [
	{ no: 1, name: 'package_id', kind: 'scalar', T: ScalarType.STRING, opt: true },
	{ no: 2, name: 'module', kind: 'scalar', T: ScalarType.STRING, opt: true },
	{ no: 3, name: 'sender', kind: 'scalar', T: ScalarType.STRING, opt: true },
	{ no: 4, name: 'event_type', kind: 'scalar', T: ScalarType.STRING, opt: true },
	{ no: 5, name: 'contents', kind: 'message', T: () => BcsMsg },
	{ no: 7, name: 'checkpoint', kind: 'scalar', T: ScalarType.UINT64, L: 0, opt: true },
	{ no: 8, name: 'transaction_digest', kind: 'scalar', T: ScalarType.STRING, opt: true },
	{ no: 10, name: 'event_index', kind: 'scalar', T: ScalarType.UINT32, opt: true },
]);

interface SenderFilter {
	address?: string;
}
const SenderFilterMsg = new MessageType<SenderFilter>('sui.rpc.v2.SenderFilter', [
	{ no: 1, name: 'address', kind: 'scalar', T: ScalarType.STRING, opt: true },
]);

interface EmitModuleFilter {
	module?: string;
}
const EmitModuleFilterMsg = new MessageType<EmitModuleFilter>('sui.rpc.v2.EmitModuleFilter', [
	{ no: 1, name: 'module', kind: 'scalar', T: ScalarType.STRING, opt: true },
]);

interface EventTypeFilter {
	eventType?: string;
}
const EventTypeFilterMsg = new MessageType<EventTypeFilter>('sui.rpc.v2.EventTypeFilter', [
	{ no: 1, name: 'event_type', kind: 'scalar', T: ScalarType.STRING, opt: true },
]);

interface EventLiteral {
	negated: boolean;
	predicate:
		| { oneofKind: 'sender'; sender: SenderFilter }
		| { oneofKind: 'emitModule'; emitModule: EmitModuleFilter }
		| { oneofKind: 'eventType'; eventType: EventTypeFilter }
		| { oneofKind: undefined };
}
const EventLiteralMsg = new MessageType<EventLiteral>('sui.rpc.v2.EventLiteral', [
	{ no: 1, name: 'negated', kind: 'scalar', T: ScalarType.BOOL },
	{ no: 2, name: 'sender', kind: 'message', oneof: 'predicate', T: () => SenderFilterMsg },
	{ no: 3, name: 'emit_module', kind: 'message', oneof: 'predicate', T: () => EmitModuleFilterMsg },
	{ no: 4, name: 'event_type', kind: 'message', oneof: 'predicate', T: () => EventTypeFilterMsg },
]);

interface EventTerm {
	literals: EventLiteral[];
}
const EventTermMsg = new MessageType<EventTerm>('sui.rpc.v2.EventTerm', [
	{ no: 1, name: 'literals', kind: 'message', repeat: 2, T: () => EventLiteralMsg },
]);

interface EventFilter {
	terms: EventTerm[];
}
const EventFilterMsg = new MessageType<EventFilter>('sui.rpc.v2.EventFilter', [
	{ no: 1, name: 'terms', kind: 'message', repeat: 2, T: () => EventTermMsg },
]);

enum Ordering {
	ASCENDING = 0,
	DESCENDING = 1,
}

interface QueryOptions {
	limit?: number;
	after?: Uint8Array;
	before?: Uint8Array;
	ordering?: Ordering;
}
const QueryOptionsMsg = new MessageType<QueryOptions>('sui.rpc.v2.QueryOptions', [
	{ no: 1, name: 'limit', kind: 'scalar', T: ScalarType.UINT32, opt: true },
	{ no: 2, name: 'after', kind: 'scalar', T: ScalarType.BYTES, opt: true },
	{ no: 3, name: 'before', kind: 'scalar', T: ScalarType.BYTES, opt: true },
	{
		no: 4,
		name: 'ordering',
		kind: 'enum',
		T: () => ['sui.rpc.v2.Ordering', Ordering],
		opt: true,
	},
]);

interface Watermark {
	cursor?: Uint8Array;
	checkpoint?: bigint;
}
const WatermarkMsg = new MessageType<Watermark>('sui.rpc.v2.Watermark', [
	{ no: 1, name: 'cursor', kind: 'scalar', T: ScalarType.BYTES, opt: true },
	{ no: 2, name: 'checkpoint', kind: 'scalar', T: ScalarType.UINT64, L: 0, opt: true },
]);

enum QueryEndReason {
	UNKNOWN = 0,
	ITEM_LIMIT = 1,
	SCAN_LIMIT = 2,
	CHECKPOINT_BOUND = 3,
	CURSOR_BOUND = 4,
	LEDGER_TIP = 5,
}

interface QueryEnd {
	reason?: QueryEndReason;
}
const QueryEndMsg = new MessageType<QueryEnd>('sui.rpc.v2.QueryEnd', [
	{
		no: 1,
		name: 'reason',
		kind: 'enum',
		T: () => ['sui.rpc.v2.QueryEndReason', QueryEndReason],
		opt: true,
	},
]);

interface ListEventsRequest {
	readMask?: FieldMask;
	startCheckpoint?: bigint;
	endCheckpoint?: bigint;
	filter?: EventFilter;
	options?: QueryOptions;
}
const ListEventsRequestMsg = new MessageType<ListEventsRequest>('sui.rpc.v2.ListEventsRequest', [
	{ no: 1, name: 'read_mask', kind: 'message', T: () => FieldMaskMsg },
	{ no: 2, name: 'start_checkpoint', kind: 'scalar', T: ScalarType.UINT64, L: 0, opt: true },
	{ no: 3, name: 'end_checkpoint', kind: 'scalar', T: ScalarType.UINT64, L: 0, opt: true },
	{ no: 4, name: 'filter', kind: 'message', T: () => EventFilterMsg },
	{ no: 5, name: 'options', kind: 'message', T: () => QueryOptionsMsg },
]);

interface ListEventsResponse {
	event?: EventProto;
	watermark?: Watermark;
	end?: QueryEnd;
}
const ListEventsResponseMsg = new MessageType<ListEventsResponse>('sui.rpc.v2.ListEventsResponse', [
	{ no: 1, name: 'event', kind: 'message', T: () => EventMsg },
	{ no: 2, name: 'watermark', kind: 'message', T: () => WatermarkMsg },
	{ no: 3, name: 'end', kind: 'message', T: () => QueryEndMsg },
]);

const LedgerServiceListEvents = new ServiceType('sui.rpc.v2.LedgerService', [
	{
		name: 'ListEvents',
		serverStreaming: true,
		clientStreaming: false,
		options: {},
		I: ListEventsRequestMsg,
		O: ListEventsResponseMsg,
	},
]);

// ── Public API ────────────────────────────────────────────────────────

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

function termToProto(term: EventQueryTerm): EventTerm {
	const literals: EventLiteral[] = [];
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

const transportCache = new Map<Network, RpcTransport>();

function transportFor(network: Network): RpcTransport {
	let transport = transportCache.get(network);
	if (!transport) {
		transport = new GrpcWebFetchTransport({ baseUrl: grpcUrlFor(network) });
		transportCache.set(network, transport);
	}
	return transport;
}

/**
 * Query indexed events from a fullnode, newest or oldest first. `anyOf` is a
 * DNF filter: terms are ORed, fields within one term are ANDed; omit it to
 * match every event in the checkpoint range.
 */
export async function listEvents(opts: {
	network: Network;
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
	const transport = transportFor(opts.network);
	const input: ListEventsRequest = {
		readMask: {
			paths: [
				'package_id',
				'module',
				'sender',
				'event_type',
				'contents',
				'checkpoint',
				'transaction_digest',
				'event_index',
			],
		},
		startCheckpoint: opts.startCheckpoint,
		endCheckpoint: opts.endCheckpoint,
		filter: opts.anyOf?.length ? { terms: opts.anyOf.map(termToProto) } : undefined,
		options: {
			limit: opts.limit,
			ordering: opts.descending ? Ordering.DESCENDING : Ordering.ASCENDING,
		},
	};

	const call = stackIntercept<ListEventsRequest, ListEventsResponse>(
		'serverStreaming',
		transport,
		LedgerServiceListEvents.methods[0],
		transport.mergeOptions({ abort: opts.signal }),
		input,
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
