// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { RistrettoPoint } from './ristretto255.js';

/**
 * Error taxonomy for the SDK. Every error the SDK raises itself extends
 * {@link ContraError}, and falls into one of five categories:
 *
 * 1. SDK invariant violations (i.e., a bug in the SDK) — {@link ContraInternalError}.
 * 2. Invalid caller arguments — {@link InvalidArgumentError}.
 * 3. Chain/account-state conditions — explicit error types.
 * 4. Cryptographic/runtime failures — explicit error types.
 * 5. Errors originating from RPC calls (timeouts, transport failures, etc.)
 *    are not wrapped but propagate to the caller untouched.
 *
 * Note: the SDK only *builds* transactions; it does not execute them. A
 * transaction returned by the SDK may still abort on chain with a Move error
 * code from the contract (e.g. a failed proof verification or a state change
 * between build and execution). Those aborts surface through the caller's
 * execution path, not as {@link ContraError}s.
 */

export class ContraError extends Error {}

/** The SDK was called with an invalid argument. */
export class InvalidArgumentError extends ContraError {}

/** Trying to spend more than the available (active or total) balance. */
export class InsufficientBalanceError extends ContraError {
	readonly amount: bigint;
	readonly spendable: bigint;
	readonly scope: 'active' | 'total';
	constructor(amount: bigint, spendable: bigint, scope: 'active' | 'total') {
		super(`Insufficient ${scope} balance for the requested amount.`);
		this.amount = amount;
		this.spendable = spendable;
		this.scope = scope;
	}
}

/**
 * One or more transfer recipients cannot accept encrypted deposits — either they
 * have explicitly paused them, or their account is frozen.
 */
export class ReceiverDoesNotAcceptDepositsError extends ContraError {
	readonly addresses: readonly string[];
	constructor(addresses: readonly string[]) {
		super(`Receivers do not accept encrypted deposits: ${addresses.join(', ')}.`);
		this.addresses = addresses;
	}
}

/** A `TokenAccount<T>` object does not exist on chain for the given owner. */
export class TokenAccountDoesNotExistError extends ContraError {
	readonly address: string;
	readonly cause: string;
	constructor(address: string, cause: string) {
		super(`Token account does not exist for ${address}: ${cause}`);
		this.address = address;
		// TODO: remove this?
		this.cause = cause;
	}
}

/** An invariant inside the SDK was violated. */
export class ContraInternalError extends ContraError {}

/** Discrete-log search exhausted the table — wrong key or plaintext out of range. */
export class DecryptionFailedError extends ContraError {
	readonly numBits: number;
	constructor(numBits: number) {
		super(
			`Decryption failed: no plaintext found in the table's 2^${numBits * 2} range (wrong key or plaintext exceeds range).`,
		);
		this.numBits = numBits;
	}
}

/**
 * A transfer was audited under an `auditorPk` this {@link ContraAuditor} holds no private key for —
 * e.g. a rotated-out key it did not retain. Add the matching key via `ContraAuditor.addKey`.
 */
export class AuditorKeyNotHeldError extends ContraError {
	readonly auditorPk: RistrettoPoint;
	constructor(auditorPk: RistrettoPoint) {
		super(
			"This auditor holds no private key matching the transfer's auditor_pk; add it with addKey.",
		);
		this.auditorPk = auditorPk;
	}
}
