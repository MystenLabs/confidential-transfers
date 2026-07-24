// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bcs } from '@mysten/sui/bcs';
import { type ClientWithCoreApi } from '@mysten/sui/client';
import {
	type Transaction,
	type TransactionObjectArgument,
	type TransactionResult,
} from '@mysten/sui/transactions';
import { deriveObjectID, normalizeStructTag, SUI_CLOCK_OBJECT_ID } from '@mysten/sui/utils';
import { type ContraPackageConfig } from 'ts-sdk';

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

	/** payment_channel::new<T>(ctx). Channel + state are shared on chain. */
	newChannel({ tokenType }: { tokenType: string }) {
		return (tx: Transaction): TransactionResult =>
			tx.moveCall({
				target: `${this.config.paymentChannelPackageId}::payment_channel::new`,
				typeArguments: [tokenType],
			});
	}

	/** payment_channel::get_auth<T>(c, ct, clock, ctx) -> Auth<T>. */
	getAuth({ channel, tokenType }: { channel: TransactionObjectArgument; tokenType: string }) {
		return (tx: Transaction): TransactionResult =>
			tx.moveCall({
				target: `${this.config.paymentChannelPackageId}::payment_channel::get_auth`,
				typeArguments: [tokenType],
				arguments: [
					channel,
					tx.object(getConfidentialTokenIdLocal(this.config, tokenType)),
					tx.object(SUI_CLOCK_OBJECT_ID),
				],
			});
	}

	/** payment_channel::activate<T>(c, receiver, end_time_ms, ctx). */
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

// Local copy of `getConfidentialTokenId` derivation to avoid pulling helpers
// not re-exported by ts-sdk's public surface.
function getConfidentialTokenIdLocal(
	config: PaymentChannelPackageConfig,
	tokenType: string,
): string {
	const normalizedType = normalizeStructTag(tokenType);
	return deriveObjectID(
		config.contra.tokenRegistryId,
		`${config.contra.packageId}::contra::TokenKey<${normalizedType}>`,
		bcs.byteVector().serialize([]).toBytes(),
	);
}
