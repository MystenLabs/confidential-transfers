// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { type Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { fromBase64 } from '@mysten/sui/utils';
import { DiscreteLogTable, EncryptedAmount, TokenAccount, TransferEventBcs } from 'ts-sdk';

import { type SignedTransfer } from './sender.ts';

/**
 * Receiver-side state machine. Holds the latest sender-signed `SignedTransfer`
 * the sender produced, after dry-running it and verifying that:
 *   - the contra `TransferEvent` to this address decrypts to exactly the
 *     receiver's current cumulative + delta;
 *   - the source matches the channel's on-chain account address (so this
 *     payment is from *our* channel, not someone else's).
 *
 * `settle` later submits the latest verified transfer with both signatures.
 */
export class Receiver {
	private accumulated = 0n;
	private latest: SignedTransfer | null = null;

	constructor(
		private readonly opts: {
			suiClient: SuiJsonRpcClient;
			walletKeypair: Ed25519Keypair;
			/** Receiver's contra TokenAccount (carries `sk_r`/`pk_r`). */
			contraTokenAccount: TokenAccount;
			tokenType: string;
			/** `payment_channel::address_of(channel)` — used to gate which channel we accept payments from. */
			channelAddress: string;
			/** Contra package id (used to identify TransferEvent type tag). */
			contraPackageId: string;
			/** Discrete-log table for decryption (typically a 32-bit table). */
			table: DiscreteLogTable;
		},
	) {}

	getAccumulated(): bigint {
		return this.accumulated;
	}

	getLatest(): SignedTransfer | null {
		return this.latest;
	}

	/**
	 * Verify a new transfer from the sender:
	 *   1. dry-run the (unsigned) tx,
	 *   2. find the `TransferEvent` paying our address,
	 *   3. decrypt and check it matches `accumulated + delta`,
	 *   4. on success, advance state and remember this as the latest.
	 *
	 * Throws on any mismatch — caller must not advance their own counter
	 * unless this returns successfully.
	 */
	async update(delta: bigint, signedTransfer: SignedTransfer): Promise<void> {
		if (delta <= 0n) throw new Error('delta must be positive');
		const expected = this.accumulated + delta;
		if (signedTransfer.cumulativeAmount !== expected) {
			throw new Error(
				`signed cumulative ${signedTransfer.cumulativeAmount} != expected ${expected}`,
			);
		}

		const dry = await this.opts.suiClient.dryRunTransactionBlock({
			transactionBlock: signedTransfer.txBytes,
		});
		if (dry.effects.status.status !== 'success') {
			throw new Error(`dry-run failed: ${dry.effects.status.error ?? 'unknown'}`);
		}

		// A settlement PTB emits exactly one contra TransferEvent; any other
		// shape is suspicious and we refuse to sign as gas sponsor.
		const myAddress = this.opts.contraTokenAccount.address;
		const transferEventType = `${this.opts.contraPackageId}::events::TransferEvent<${this.opts.tokenType}>`;
		const transferEvents = dry.events.filter((ev) => ev.type === transferEventType);
		if (transferEvents.length !== 1) {
			throw new Error(`expected 1 TransferEvent, found ${transferEvents.length}`);
		}
		const ev = transferEvents[0];
		const raw = typeof ev.bcs === 'string' ? fromBase64(ev.bcs) : (ev.bcs as Uint8Array);
		const parsed = TransferEventBcs.parse(raw);
		if (parsed.sender !== this.opts.channelAddress) {
			throw new Error(
				`TransferEvent sender ${parsed.sender} != channel ${this.opts.channelAddress}`,
			);
		}
		if (parsed.receiver !== myAddress) {
			throw new Error(`TransferEvent receiver ${parsed.receiver} != ${myAddress}`);
		}
		const foundAmount = this.opts.contraTokenAccount.decryptAmount(
			EncryptedAmount.fromBcs(parsed.encrypted_amount_receiver),
			this.opts.table,
		);
		if (foundAmount !== expected) {
			throw new Error(`decrypted amount ${foundAmount} != expected ${expected}`);
		}

		this.accumulated = expected;
		this.latest = signedTransfer;
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
		return await this.opts.suiClient.executeTransactionBlock({
			transactionBlock: this.latest.txBytes,
			signature: [this.latest.senderSignature, sponsorSignature],
			options: { showEffects: true, showEvents: true, showObjectChanges: true },
		});
	}
}
