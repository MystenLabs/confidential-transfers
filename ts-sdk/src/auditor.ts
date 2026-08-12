// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bytesToHex } from '@noble/curves/utils.js';

import { TransferEvent } from './contracts/contra/events.js';
import { AuditorKeyNotHeldError } from './error.js';
import { G, mul, pointFromBcs, type RistrettoPoint } from './ristretto255.js';
import { Ciphertext, type DiscreteLogTable, type PrivateKey } from './twisted_elgamal.js';
import type { ContraAuditorOptions } from './types.js';

const SHIFT_32 = 1n << 32n;

/**
 * A decoded `TransferEvent` an auditor reads (`TransferEventBcs.parse`). This is the inferred type of
 * the generated `events::TransferEvent` BCS schema, so it tracks the Move struct automatically — but
 * only after `pnpm codegen` is re-run when that struct changes.
 */
export type DecodedTransferEvent = typeof TransferEvent.$inferType;

/**
 * Per-transfer auditor SDK. Under per-transfer auditing the auditor never learns a user's viewing
 * key; instead every transfer carries an auditor-readable copy of the amount under the token's auditor
 * key. A `TransferEvent` names that key in `auditor_pk` and carries its `[lo, hi]` handles in
 * `auditor_decryption_handle` (both `none` when auditing is disabled). The event's
 * `encrypted_amount_receiver` already carries the two u32-limb commitments (`Ǎ_0, Ǎ_1`), so this pairs
 * each with the matching handle to form a twisted ElGamal ciphertext and recovers the amount.
 *
 * A token has at most one auditor key at a time, but it can be rotated, and a transfer made before a
 * rotation stays encrypted under whichever key was current then (accepted on chain during the grace
 * window, and readable off-chain forever). An auditor holds one or more private keys so it can read
 * across rotations: construct it with every key it has ever held — or add rotated-out keys later with
 * `addKey` — and `decryptTransferAmount` uses the held key whose public key (`pk = sk * G`) matches the
 * transfer's `auditor_pk`.
 */
export class ContraAuditor {
	#tokenType: string;
	// Keyed by the hex of the public key's compressed bytes, so a transfer's `auditor_pk` (the same
	// canonical encoding) is a direct lookup rather than a scan over every held key.
	#keys: Map<string, { publicKey: RistrettoPoint; privateKey: PrivateKey }>;
	#table: DiscreteLogTable;

	constructor(options: ContraAuditorOptions) {
		this.#tokenType = options.tokenType;
		this.#table = options.table;
		this.#keys = new Map();
		for (const privateKey of options.privateKeys) this.addKey(privateKey);
	}

	get tokenType(): string {
		return this.#tokenType;
	}

	/** The auditor public keys this instance can decrypt transfers for (`pk = sk * G`). */
	get publicKeys(): RistrettoPoint[] {
		return [...this.#keys.values()].map((k) => k.publicKey);
	}

	/**
	 * Register an auditor private key so transfers whose `auditor_pk` is its public key (`pk = sk * G`)
	 * become decryptable — e.g. adding a rotated-out key to keep reading transfers made before the
	 * rotation. A no-op if the key is already held.
	 */
	addKey(privateKey: PrivateKey): void {
		const publicKey = mul(G, privateKey);
		this.#keys.set(bytesToHex(publicKey.toBytes()), { publicKey, privateKey });
	}

	/**
	 * Recover the transferred amount from a `TransferEvent`. If a held key matches the event's
	 * `auditor_pk`, pairs each of the event's two u32-limb commitments (`encrypted_amount_receiver`)
	 * with the matching `auditor_decryption_handle` and BSGS-decrypts.
	 *
	 * @param event a decoded `TransferEvent` (`TransferEventBcs.parse`).
	 * @returns the transferred amount, or `null` if the transfer carried no auditor data (auditing was
	 *   disabled for it).
	 * @throws {@link AuditorKeyNotHeldError} if this auditor doesn't hold the event's `auditor_pk`;
	 *   {@link DecryptionFailedError} if a u32 limb is outside the decryption table's range.
	 */
	decryptTransferAmount(event: DecodedTransferEvent): bigint | null {
		const auditorPk = event.auditor_pk;
		const pair = event.auditor_decryption_handle;
		// No auditor data attached (auditing was disabled for this transfer).
		if (auditorPk === null || pair === null) return null;
		const held = this.#keys.get(bytesToHex(Uint8Array.from(auditorPk.element.bytes)));
		if (held === undefined) {
			throw new AuditorKeyNotHeldError(pointFromBcs(auditorPk.element));
		}
		if (pair.length !== 2) return null;
		// The event already carries the two u32-limb commitments (`Ǎ_0, Ǎ_1`); pair each with the
		// auditor's matching handle and BSGS-decrypt.
		const d0 = pointFromBcs(pair[0]);
		const d1 = pointFromBcs(pair[1]);
		const a0 = pointFromBcs(event.encrypted_amount_receiver[0].ciphertext);
		const a1 = pointFromBcs(event.encrypted_amount_receiver[1].ciphertext);
		const n0 = new Ciphertext(a0, d0).decrypt(held.privateKey, this.#table);
		const n1 = new Ciphertext(a1, d1).decrypt(held.privateKey, this.#table);
		return n0 + n1 * SHIFT_32;
	}
}
