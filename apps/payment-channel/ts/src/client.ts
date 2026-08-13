// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type ClientWithCoreApi } from '@mysten/sui/client';
import {
	type Transaction,
	type TransactionObjectArgument,
	type TransactionResult,
} from '@mysten/sui/transactions';
import { SUI_CLOCK_OBJECT_ID } from '@mysten/sui/utils';
import { getConfidentialTokenId, type ContraPackageConfig } from 'ts-sdk';

export type PaymentChannelPackageConfig = {
	paymentChannelPackageId: string;
	contra: ContraPackageConfig;
};

/**
 * Move-call builders for the `payment_channel` module's three public ops:
 * `new`, `get_auth`, and `activate`. Every actual contra operation —
 * including bringing the channel's `Account` up — is composed by the caller
 * using `ContraClient` with the `Auth<T>` returned by `getAuth`.
 */
export class PaymentChannelClient {
	readonly suiClient: ClientWithCoreApi;
	readonly config: PaymentChannelPackageConfig;

	constructor(opts: { suiClient: ClientWithCoreApi; config: PaymentChannelPackageConfig }) {
		this.suiClient = opts.suiClient;
		this.config = opts.config;
	}

	channelType(tokenType: string): string {
		return `${this.config.paymentChannelPackageId}::payment_channel::Channel<${tokenType}>`;
	}

	newChannel({ tokenType }: { tokenType: string }) {
		return (tx: Transaction): TransactionResult =>
			tx.moveCall({
				target: `${this.config.paymentChannelPackageId}::payment_channel::new`,
				typeArguments: [tokenType],
			});
	}

	getAuth({ channel, tokenType }: { channel: TransactionObjectArgument; tokenType: string }) {
		return (tx: Transaction): TransactionResult =>
			tx.moveCall({
				target: `${this.config.paymentChannelPackageId}::payment_channel::get_auth`,
				typeArguments: [tokenType],
				arguments: [
					channel,
					tx.object(getConfidentialTokenId(this.config.contra, tokenType)),
					tx.object(SUI_CLOCK_OBJECT_ID),
				],
			});
	}

	activate({
		channel,
		receiver,
		endTimeMs,
		tokenType,
	}: {
		channel: TransactionObjectArgument;
		receiver: string;
		endTimeMs: bigint;
		tokenType: string;
	}) {
		return (tx: Transaction): TransactionResult =>
			tx.moveCall({
				target: `${this.config.paymentChannelPackageId}::payment_channel::activate`,
				typeArguments: [tokenType],
				arguments: [channel, tx.pure.address(receiver), tx.pure.u64(endTimeMs)],
			});
	}
}
