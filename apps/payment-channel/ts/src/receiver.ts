// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bcs } from '@mysten/sui/bcs';
import { type ClientWithCoreApi } from '@mysten/sui/client';
import { type Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeStructTag, normalizeSuiAddress } from '@mysten/sui/utils';
import { DiscreteLogTable, EncryptedAmount, TokenAccount, TransferEventBcs } from 'ts-sdk';

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
 * Note: a held transfer embeds auditor data built against the token's auditor
 * key at signing time. After the issuer rotates that key, it stays settleable
 * only during the token's rotation grace window (`previous_pks`), so the
 * receiver should know the token's official grace policy and settle — or ask
 * the sender to re-sign — before the window closes.
 */
export class Receiver {
	private accumulated = 0n;
	private latest: SignedTransfer | null = null;
	private channel: { sender: string; endTimeMs: bigint } | null = null;

	constructor(
		private readonly opts: {
			suiClient: ClientWithCoreApi;
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
		this.channel = { sender: normalizeSuiAddress(parsed.sender), endTimeMs };
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
