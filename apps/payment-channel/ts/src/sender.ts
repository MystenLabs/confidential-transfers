// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ClientWithCoreApi } from '@mysten/sui/client';
import { type Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { ContraClient, type TokenAccount } from 'ts-sdk';

import { PaymentChannelClient } from './client.ts';

export type GasCoinRef = {
	objectId: string;
	version: string | number;
	digest: string;
};

export type SignedTransfer = {
	cumulativeAmount: bigint;
	txBytes: Uint8Array;
	senderSignature: string;
};

/**
 * Sender-side state machine. `transfer(delta)` advances the running cumulative
 * amount and produces a sender-signed sponsored tx that pays the new
 * cumulative to the channel receiver. The receiver dry-runs to verify the
 * encrypted amount, signs as gas sponsor, and broadcasts; on chain that tx
 * flips channel state to `Closed`. The sender then calls `sweep()` to recover
 * the residual.
 *
 * Each settlement is a `get_auth → [merge →] transfer` PTB built by
 * `contraClient.transfer({ ..., auth, merge: true })`: when the channel
 * still has pending deposits (the wrapped amount until the first
 * settlement), `transfer` prepends a merge under the channel auth and
 * computes its proofs against the post-merge balance. The "merge succeeded
 * but transfer failed" race that motivates `merge: false` elsewhere can't
 * fire here — only the channel sender deposits, and they stop after
 * activate.
 */
export class Sender {
	private cumulativeAmount = 0n;

	constructor(
		private readonly opts: {
			suiClient: ClientWithCoreApi;
			contraClient: ContraClient;
			paymentChannelClient: PaymentChannelClient;
			walletKeypair: Ed25519Keypair;
			tokenType: string;
			channelObjectId: string;
			/** TokenAccount for the channel's contra account (carries pk_c / sk_c). */
			channelTokenAccount: TokenAccount;
			/** Channel receiver wallet — gas sponsor of receiver-driven settlements. */
			receiverAddress: string;
			/** Where `sweep()` deposits the residual; typically the sender's own contra account. */
			sweepDestAddress: string;
		},
	) {}

	getCumulativeAmount(): bigint {
		return this.cumulativeAmount;
	}

	async transfer(
		delta: bigint,
		sponsorGasCoin: GasCoinRef,
		gasBudget: bigint = 200_000_000n,
	): Promise<SignedTransfer> {
		if (delta <= 0n) throw new Error('delta must be positive');
		const cumulative = this.cumulativeAmount + delta;
		const txBytes = await this.#buildTxBytes({
			amount: cumulative,
			recipientAddress: this.opts.receiverAddress,
			sponsorAddress: this.opts.receiverAddress,
			sponsorGasCoin,
			gasBudget,
		});
		const { signature: senderSignature } = await this.opts.walletKeypair.signTransaction(txBytes);
		this.cumulativeAmount = cumulative;
		return { cumulativeAmount: cumulative, txBytes, senderSignature };
	}

	/**
	 * Sweep the channel's current on-chain residual to `sweepDestAddress`.
	 * Submits with sender as both `ctx.sender` and gas sponsor.
	 *
	 * Sweeps `active + pending` since the timeout path leaves the wrapped
	 * funds in pending (no settlement ever ran a merge). The sweep PTB also
	 * uses `merge: true` so the prepended merge under the channel auth
	 * flushes pending into active before the transfer.
	 *
	 * Aborts on chain with `EChannelActive` unless the channel state is no
	 * longer `Active` (receiver settled, or `clock.now >= end_time_ms`).
	 */
	async sweep(senderGasCoin: GasCoinRef, gasBudget: bigint = 200_000_000n) {
		const { balance, pending, pendingPublicBalance } = await this.opts.contraClient.getBalance(
			this.opts.channelTokenAccount,
		);
		const total = balance.amount + pending.amount + pendingPublicBalance;
		if (total === 0n) throw new Error('channel residual is zero — nothing to sweep');
		const txBytes = await this.#buildTxBytes({
			amount: total,
			recipientAddress: this.opts.sweepDestAddress,
			sponsorAddress: this.opts.walletKeypair.toSuiAddress(),
			sponsorGasCoin: senderGasCoin,
			gasBudget,
		});
		const { signature } = await this.opts.walletKeypair.signTransaction(txBytes);
		return await this.opts.suiClient.core.executeTransaction({
			transaction: txBytes,
			signatures: [signature],
			include: { effects: true, events: true },
		});
	}

	async #buildTxBytes(opts: {
		amount: bigint;
		recipientAddress: string;
		sponsorAddress: string;
		sponsorGasCoin: GasCoinRef;
		gasBudget: bigint;
	}): Promise<Uint8Array> {
		const tx = new Transaction();
		// Auth-builder thunk: `contra::transfer` mints one `Auth<T>` and reuses the
		// reference for every call it makes (the inline merge under the channel auth and
		// the transfer itself), so this thunk runs once and emits a single
		// `payment_channel::get_auth`. That call flips channel state Active → Closed and
		// returns the auth shared by both calls.
		const authThunk = (innerTx: Transaction) =>
			innerTx.add(
				this.opts.paymentChannelClient.getAuth({
					channel: innerTx.object(this.opts.channelObjectId),
					tokenType: this.opts.tokenType,
				}),
			);
		const transferThunk = await this.opts.contraClient.transfer({
			tokenAccount: this.opts.channelTokenAccount,
			receiverAddress: opts.recipientAddress,
			amount: opts.amount,
			auth: authThunk,
			merge: true,
		});
		tx.add(transferThunk);

		tx.setSender(this.opts.walletKeypair.toSuiAddress());
		tx.setGasOwner(opts.sponsorAddress);
		tx.setGasPayment([opts.sponsorGasCoin]);
		tx.setGasBudget(opts.gasBudget);
		return await tx.build({ client: this.opts.suiClient });
	}
}
