// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bcs } from '@mysten/sui/bcs';
import { type SuiGrpcClient } from '@mysten/sui/grpc';
import { type Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeStructTag, normalizeSuiAddress } from '@mysten/sui/utils';
import { checkpointTimestampMs, listEvents } from 'contra-utils';
import {
	contraContracts,
	DiscreteLogTable,
	EncryptedAmount,
	eventsContracts,
	TokenAccount,
	TransferEventBcs,
} from 'ts-sdk';

import { type SignedTransfer } from './sender.ts';

/** BCS layout of the on-chain `payment_channel::Channel<T>` object. */
const ChannelBcs = bcs.struct('Channel', {
	id: bcs.Address,
	sender: bcs.Address,
	state: bcs.enum('State', {
		Initialized: null,
		Active: bcs.struct('Active', { receiver: bcs.Address, end_time_ms: bcs.u64() }),
		Closed: null,
	}),
});

/** Default cap on the gas budget the receiver is willing to sponsor (0.2 SUI). */
const DEFAULT_MAX_GAS_BUDGET = 200_000_000n;

function bytesEqual(a: number[], b: Uint8Array): boolean {
	return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/**
 * Receiver-side state machine. `init()` runs the channel acceptance checks and
 * must be awaited before `update()`. `update()` then vets each sender-signed
 * `SignedTransfer` twice over:
 *
 * Structurally (from the raw tx bytes, before any network call):
 *   - the tx sender is the channel's on-chain `sender`;
 *   - the receiver only sponsors the expected gas: gas owner is this wallet
 *     and the budget is within `maxGasBudget`;
 *   - no expiration is set (an expiring tx could silently invalidate the
 *     held settlement);
 *   - every command is on the settlement whitelist — in particular exactly
 *     one `payment_channel::get_auth`, and it targets *this* channel (a
 *     hidden `get_auth` on another channel with the same receiver would
 *     close that channel unpaid), and no `contra::merge` (a merge makes the
 *     proofs depend on the pending balance, which anyone can grief with a
 *     deposit; combined with `try_finalize`'s soft-fail that would close
 *     the channel without paying).
 *
 * Semantically (via dry-run):
 *   - the contra `TransferEvent` to this address decrypts to exactly the
 *     receiver's current cumulative + delta;
 *   - the source matches the channel's on-chain account address (so this
 *     payment is from *our* channel, not someone else's).
 *
 * `settle` later submits the latest verified transfer with both signatures.
 *
 * ## Auditor-key rotations and the grace period
 *
 * A held transfer embeds auditor data built against the token's auditor key at
 * signing time. After the issuer rotates that key, the transfer stays
 * settleable only while the old key remains in the token's `previous_pks`
 * grace set — so running a channel REQUIRES a token whose issuer publishes a
 * known rotation grace period (e.g. 1 day) and honors it in `update_auditors`.
 * The receiver pins the expected auditor key (`auditorPk`, `null` for a token
 * with auditing disabled) and the published grace period (`gracePeriodMs`) at
 * construction; `init()` checks the pin against the token's `current_pks`, and
 * `lastTimeToSettle()` watches for a change: it returns `null` while the
 * pinned configuration is still current, and otherwise the deadline (unix ms)
 * by which the held transfer must be settled.
 */
export class Receiver {
	private accumulated = 0n;
	private latest: SignedTransfer | null = null;
	private channel: { sender: string; endTimeMs: bigint } | null = null;

	constructor(
		private readonly opts: {
			suiClient: SuiGrpcClient;
			walletKeypair: Ed25519Keypair;
			/** Receiver's contra TokenAccount (carries `sk_r`/`pk_r`). */
			contraTokenAccount: TokenAccount;
			tokenType: string;
			/** `payment_channel::address_of(channel)` — equals the channel object id. */
			channelAddress: string;
			/** Contra package id (used to identify TransferEvent type tag and whitelist calls). */
			contraPackageId: string;
			/** payment_channel package id (used to whitelist the `get_auth` call). */
			paymentChannelPackageId: string;
			/** The shared `ConfidentialToken<tokenType>` object id. */
			confidentialTokenId: string;
			/**
			 * The auditor public key (32-byte compressed ristretto point) held transfers are built
			 * against, or `null` for a token with auditing disabled. `init()` checks it against the
			 * token's `current_pks`; `lastTimeToSettle()` watches for it to rotate out.
			 */
			auditorPk: Uint8Array | null;
			/** The token's published auditor-rotation grace period, in ms (e.g. 1 day). */
			gracePeriodMs: bigint;
			/** Discrete-log table for decryption (typically a 32-bit table). */
			table: DiscreteLogTable;
			/** Cap on the sponsored gas budget. Defaults to 0.2 SUI. */
			maxGasBudget?: bigint;
		},
	) {}

	getAccumulated(): bigint {
		return this.accumulated;
	}

	getLatest(): SignedTransfer | null {
		return this.latest;
	}

	/** `end_time_ms` of the accepted channel. Only available after `init()`. */
	getEndTimeMs(): bigint {
		if (!this.channel) throw new Error('call init() first');
		return this.channel.endTimeMs;
	}

	/**
	 * Fetch the on-chain `Channel<T>` and run the acceptance checks before
	 * agreeing to use it:
	 *   - the object exists and its type is exactly
	 *     `payment_channel::Channel<tokenType>` from the expected package;
	 *   - state is `Active` (funded and locked);
	 *   - `Active.receiver` is this wallet;
	 *   - at least `minRemainingMs` remain until `end_time_ms`, leaving
	 *     comfortable time to settle.
	 * Stores the channel's `sender` and deadline for the per-transfer checks.
	 * Must be awaited before `update()`.
	 */
	async init(minRemainingMs: bigint = 60_000n): Promise<void> {
		const {
			objects: [object],
		} = await this.opts.suiClient.core.getObjects({
			objectIds: [this.opts.channelAddress],
			include: { content: true },
		});
		if (object instanceof Error) {
			throw new Error(`channel object not found: ${object.message}`);
		}
		const expectedType = normalizeStructTag(
			`${this.opts.paymentChannelPackageId}::payment_channel::Channel<${this.opts.tokenType}>`,
		);
		if (normalizeStructTag(object.type) !== expectedType) {
			throw new Error(`object ${this.opts.channelAddress} is a ${object.type}, not a Channel`);
		}
		const parsed = ChannelBcs.parse(object.content);
		if (parsed.state.$kind !== 'Active') {
			throw new Error(`channel is ${parsed.state.$kind}, not Active`);
		}
		const { receiver, end_time_ms } = parsed.state.Active;
		const myAddress = normalizeSuiAddress(this.opts.walletKeypair.toSuiAddress());
		if (normalizeSuiAddress(receiver) !== myAddress) {
			throw new Error(`channel receiver ${receiver} is not this wallet ${myAddress}`);
		}
		const endTimeMs = BigInt(end_time_ms);
		if (BigInt(Date.now()) + minRemainingMs > endTimeMs) {
			throw new Error(
				`channel end_time_ms ${endTimeMs} leaves less than ${minRemainingMs}ms to settle`,
			);
		}
		// The pinned auditor expectation must hold when the channel is accepted: transfers signed
		// from here on embed auditor data for exactly this configuration.
		const auditors = await this.fetchAuditors();
		if (!this.matchesPinnedAuditor(auditors.current_pks)) {
			throw new Error(
				this.opts.auditorPk === null
					? "expected the token's auditing to be disabled, but it has a current auditor key"
					: "the token's current auditor key does not match the pinned auditorPk",
			);
		}
		this.channel = { sender: normalizeSuiAddress(parsed.sender), endTimeMs };
	}

	/**
	 * The deadline (unix ms) by which the held transfer must be settled, or `null` while the
	 * pinned auditor configuration is still the token's current one (no deadline). Once the
	 * configuration changes, the deadline is the on-chain `UpdateAuditorsEvent` time plus
	 * `gracePeriodMs` — or the change time itself where settleability ends immediately (auditing
	 * enabled on a pinned-`null` token; the pinned key dropped from `previous_pks`). A returned
	 * deadline in the past means the held transfer can no longer settle: ask the sender to re-sign.
	 */
	async lastTimeToSettle(): Promise<bigint | null> {
		const auditors = await this.fetchAuditors();
		if (this.matchesPinnedAuditor(auditors.current_pks)) return null;

		// The pinned configuration is no longer current: walk the token's auditor updates
		// oldest-first to find when it stopped holding (and, for a rotation with grace, whether a
		// later update dropped the key from `previous_pks` early).
		const contraPkg = normalizeSuiAddress(this.opts.contraPackageId);
		const eventType = normalizeStructTag(
			`${contraPkg}::events::UpdateAuditorsEvent<${this.opts.tokenType}>`,
		);
		const updates = await listEvents({
			client: this.opts.suiClient,
			anyOf: [{ eventType: `${contraPkg}::events::UpdateAuditorsEvent` }],
		});

		// Track the latest streak of updates under which the pinned configuration does not hold:
		// an update restoring it resets the streak; within a streak the deadline is its start plus
		// the grace period, capped at the first update that ends settleability outright (auditing
		// enabled on a pinned-`null` token aborts no-data transfers immediately; a key dropped
		// from `previous_pks` loses its grace at that moment).
		let deadlineMs: bigint | null = null;
		for (const ev of updates) {
			if (normalizeStructTag(ev.eventType) !== eventType || ev.checkpoint === undefined) {
				continue;
			}
			const parsed = eventsContracts.UpdateAuditorsEvent.parse(ev.bcs);
			if (this.matchesPinnedAuditor(parsed.current_pks)) {
				deadlineMs = null;
				continue;
			}
			const tMs = await checkpointTimestampMs(this.opts.suiClient, ev.checkpoint);
			if (tMs === undefined) continue;
			const pinned = this.opts.auditorPk;
			if (deadlineMs === null) {
				deadlineMs = pinned === null ? BigInt(tMs) : BigInt(tMs) + this.opts.gracePeriodMs;
			}
			if (pinned !== null) {
				const inPrevious = parsed.previous_pks.some((pk) =>
					bytesEqual(pk.element.bytes, pinned),
				);
				if (!inPrevious && BigInt(tMs) < deadlineMs) deadlineMs = BigInt(tMs);
			}
		}
		if (deadlineMs === null) {
			throw new Error('auditor configuration changed but no matching UpdateAuditorsEvent found');
		}
		return deadlineMs;
	}

	/** Fetch and parse the token's on-chain `Auditors` configuration. */
	private async fetchAuditors() {
		const {
			objects: [object],
		} = await this.opts.suiClient.core.getObjects({
			objectIds: [this.opts.confidentialTokenId],
			include: { content: true },
		});
		if (object instanceof Error) {
			throw new Error(`confidential token object not found: ${object.message}`);
		}
		return contraContracts.ConfidentialToken.parse(object.content).auditors;
	}

	/** Whether `currentPks` is exactly the pinned auditor configuration. */
	private matchesPinnedAuditor(currentPks: { element: { bytes: number[] } }[]): boolean {
		const pinned = this.opts.auditorPk;
		if (pinned === null) return currentPks.length === 0;
		return currentPks.length === 1 && bytesEqual(currentPks[0].element.bytes, pinned);
	}

	/**
	 * Verify a new transfer from the sender:
	 *   1. structurally verify the raw PTB (see the class doc),
	 *   2. dry-run the (unsigned) tx,
	 *   3. find the `TransferEvent` paying our address,
	 *   4. decrypt and check it matches `accumulated + delta`,
	 *   5. on success, advance state and remember this as the latest.
	 *
	 * Throws on any mismatch — caller must not advance their own counter
	 * unless this returns successfully.
	 */
	async update(delta: bigint, signedTransfer: SignedTransfer): Promise<void> {
		if (!this.channel) throw new Error('call init() first');
		if (delta <= 0n) throw new Error('delta must be positive');
		if (BigInt(Date.now()) >= this.channel.endTimeMs) {
			throw new Error('channel end_time_ms has passed — the sender can reclaim at any moment');
		}
		const expected = this.accumulated + delta;
		if (signedTransfer.cumulativeAmount !== expected) {
			throw new Error(
				`signed cumulative ${signedTransfer.cumulativeAmount} != expected ${expected}`,
			);
		}

		this.verifyPtbStructure(signedTransfer.txBytes);

		const dry = await this.opts.suiClient.core.simulateTransaction({
			transaction: signedTransfer.txBytes,
			include: { events: true },
		});
		if (dry.FailedTransaction) {
			throw new Error(
				`dry-run failed: ${dry.FailedTransaction.status.error?.message ?? 'unknown'}`,
			);
		}

		// A settlement PTB emits exactly one contra TransferEvent; any other
		// shape is suspicious and we refuse to sign as gas sponsor.
		const myAddress = this.opts.contraTokenAccount.address;
		const transferEventType = `${this.opts.contraPackageId}::events::TransferEvent<${this.opts.tokenType}>`;
		const transferEvents = dry.Transaction.events.filter(
			(ev) => ev.eventType === transferEventType,
		);
		if (transferEvents.length !== 1) {
			throw new Error(`expected 1 TransferEvent, found ${transferEvents.length}`);
		}
		const parsed = TransferEventBcs.parse(transferEvents[0].bcs);
		if (parsed.sender !== this.opts.channelAddress) {
			throw new Error(
				`TransferEvent sender ${parsed.sender} != channel ${this.opts.channelAddress}`,
			);
		}
		if (parsed.receiver !== myAddress) {
			throw new Error(`TransferEvent receiver ${parsed.receiver} != ${myAddress}`);
		}
		const receiverAmount = EncryptedAmount.fromBcs(parsed.encrypted_amount_receiver);
		const foundAmount = this.opts.contraTokenAccount.decryptAmount(
			[receiverAmount.l0, receiverAmount.l1, receiverAmount.l2, receiverAmount.l3],
			this.opts.table,
		);
		if (foundAmount !== expected) {
			throw new Error(`decrypted amount ${foundAmount} != expected ${expected}`);
		}

		this.accumulated = expected;
		this.latest = signedTransfer;
	}

	/**
	 * Structural whitelist over the sender-signed tx bytes.
	 */
	private verifyPtbStructure(txBytes: Uint8Array): void {
		const channel = this.channel!;
		const data = Transaction.from(txBytes).getData();
		const myAddress = normalizeSuiAddress(this.opts.walletKeypair.toSuiAddress());
		const contraPkg = normalizeSuiAddress(this.opts.contraPackageId);
		const pcPkg = normalizeSuiAddress(this.opts.paymentChannelPackageId);
		const channelId = normalizeSuiAddress(this.opts.channelAddress);
		const maxGasBudget = this.opts.maxGasBudget ?? DEFAULT_MAX_GAS_BUDGET;

		if (!data.sender || normalizeSuiAddress(data.sender) !== channel.sender) {
			throw new Error(`tx sender ${data.sender} is not the channel sender ${channel.sender}`);
		}
		if (data.expiration && data.expiration.$kind !== 'None') {
			throw new Error('settlement tx must not carry an expiration');
		}
		if (!data.gasData.owner || normalizeSuiAddress(data.gasData.owner) !== myAddress) {
			throw new Error(`gas owner ${data.gasData.owner} is not this wallet`);
		}
		if (data.gasData.budget == null || BigInt(data.gasData.budget) > maxGasBudget) {
			throw new Error(`gas budget ${data.gasData.budget} exceeds cap ${maxGasBudget}`);
		}

		// Functions of `contra::contra` a settlement may call. Deliberately
		// excludes `merge` and everything else.
		const contraFns = new Set(['batched_transfer', 'add_to_batch', 'finalize', 'try_finalize']);
		// Contra modules that only build verified values and mutate nothing.
		const contraPureModules = new Set([
			'decode',
			'encrypted_amount',
			'range_proof',
			'auditors',
			'twisted_elgamal',
			'nizk',
		]);

		let getAuthCalls = 0;
		for (const command of data.commands) {
			if (command.$kind === 'MakeMoveVec') continue;
			if (command.$kind !== 'MoveCall') {
				throw new Error(`disallowed command in settlement tx: ${command.$kind}`);
			}
			const call = command.MoveCall;
			const pkg = normalizeSuiAddress(call.package);
			if (pkg === pcPkg && call.module === 'payment_channel' && call.function === 'get_auth') {
				getAuthCalls++;
				const arg = call.arguments[0];
				const input = arg?.$kind === 'Input' ? data.inputs[arg.Input] : undefined;
				const objectId =
					input?.$kind === 'Object' && input.Object.$kind === 'SharedObject'
						? normalizeSuiAddress(input.Object.SharedObject.objectId)
						: undefined;
				if (objectId !== channelId) {
					throw new Error('get_auth must target this channel');
				}
				continue;
			}
			if (pkg === contraPkg) {
				if (call.module === 'contra' && contraFns.has(call.function)) continue;
				if (contraPureModules.has(call.module)) continue;
			}
			if (pkg === normalizeSuiAddress('0x1') && call.module === 'option') continue;
			if (pkg === normalizeSuiAddress('0x2') && call.module === 'ristretto255') continue;
			throw new Error(
				`disallowed move call in settlement tx: ${call.package}::${call.module}::${call.function}`,
			);
		}
		if (getAuthCalls !== 1) {
			throw new Error(`expected exactly 1 get_auth call, found ${getAuthCalls}`);
		}
	}

	/**
	 * Sign the most recently verified transfer as gas sponsor and submit it
	 * for execution. Returns the executed transaction effects (digest etc.).
	 */
	async settle() {
		if (!this.latest) throw new Error('no signed transfer to settle');
		const { signature: sponsorSignature } = await this.opts.walletKeypair.signTransaction(
			this.latest.txBytes,
		);
		return await this.opts.suiClient.core.executeTransaction({
			transaction: this.latest.txBytes,
			signatures: [this.latest.senderSignature, sponsorSignature],
			include: { effects: true, events: true },
		});
	}
}
