// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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
 * key; instead every transfer carries one auditor-readable ciphertext set per auditor key. A token
 * can have several auditors, so a `TransferEvent` lists `auditor_pks` and, at matching indices,
 * `auditor_decryption_handles` (two u32-limb handles per key). The event's `encrypted_amount_receiver`
 * already carries the two u32-limb commitments (`Ǎ_0, Ǎ_1`), so this pairs each with the matching
 * handle to form a twisted ElGamal ciphertext and recovers the transferred amount with a held key.
 *
 * An auditor holds one or more private keys. A token's auditor keys can be rotated, and a transfer
 * made before a rotation stays encrypted under whichever keys were current then (accepted on chain
 * during the grace window, and readable off-chain forever). To decrypt across rotations, construct
 * the auditor with every key it has ever held — or add rotated-out keys later with `addKey` —
 * and `decryptTransferAmount` selects the private key whose public key (`pk = sk * G`) matches one of
 * the transfer's `auditor_pks`.
 */
export class ContraAuditor {
	#tokenType: string;
	#keys: { publicKey: RistrettoPoint; privateKey: PrivateKey }[];
	#table: DiscreteLogTable;

	constructor(options: ContraAuditorOptions) {
		this.#tokenType = options.tokenType;
		this.#table = options.table;
		this.#keys = [];
		for (const privateKey of options.privateKeys) this.addKey(privateKey);
	}

	get tokenType(): string {
		return this.#tokenType;
	}

	/** The auditor public keys this instance can decrypt transfers for (`pk = sk * G`). */
	get publicKeys(): RistrettoPoint[] {
		return this.#keys.map((k) => k.publicKey);
	}

	/**
	 * Register an auditor private key so transfers whose `auditor_pk` is its public key (`pk = sk * G`)
	 * become decryptable — e.g. adding a rotated-out key to keep reading transfers made before the
	 * rotation. A no-op if the key is already held.
	 */
	addKey(privateKey: PrivateKey): void {
		const publicKey = mul(G, privateKey);
		if (this.#keys.some((k) => k.publicKey.equals(publicKey))) return;
		this.#keys.push({ publicKey, privateKey });
	}

	/**
	 * Recover the transferred amount from a `TransferEvent`, using the held key whose public key matches
	 * one of the event's `auditor_pks`, and that key's handles (at the same index in
	 * `auditor_decryption_handles`). Pairs each of the event's two u32-limb commitments
	 * (`encrypted_amount_receiver`) with the matching handle and BSGS-decrypts.
	 *
	 * @param event a decoded `TransferEvent` (`TransferEventBcs.parse`).
	 * @returns the transferred amount, or `null` if the transfer carried no auditor data (auditing was
	 *   disabled for it).
	 * @throws {@link AuditorKeyNotHeldError} if this auditor holds no key matching any of the event's
	 *   `auditor_pks`; {@link DecryptionFailedError} if a u32 limb is outside the decryption table's range.
	 */
	decryptTransferAmount(event: DecodedTransferEvent): bigint | null {
		const auditorPks = event.auditor_pks;
		// No auditor data attached (auditing was disabled for this transfer).
		if (auditorPks.length === 0) return null;
		// Find the transfer's auditor key this instance holds a matching private key for. Each key's
		// handles sit at the same index in `auditor_decryption_handles`.
		let index = -1;
		let privateKey: PrivateKey | undefined;
		for (const [i, pkBcs] of auditorPks.entries()) {
			const held = this.#keys.find((k) => k.publicKey.equals(pointFromBcs(pkBcs.element)));
			if (held) {
				index = i;
				privateKey = held.privateKey;
				break;
			}
		}
		if (privateKey === undefined) {
			throw new AuditorKeyNotHeldError(pointFromBcs(auditorPks[0].element));
		}
		const handles = event.auditor_decryption_handles[index];
		if (handles === undefined || handles.length !== 2) return null;
		// The event already carries the two u32-limb commitments (`Ǎ_0, Ǎ_1`); pair each with this
		// auditor's matching handle and BSGS-decrypt.
		const d0 = pointFromBcs(handles[0]);
		const d1 = pointFromBcs(handles[1]);
		const a0 = pointFromBcs(event.encrypted_amount_receiver[0].ciphertext);
		const a1 = pointFromBcs(event.encrypted_amount_receiver[1].ciphertext);
		const n0 = new Ciphertext(a0, d0).decrypt(privateKey, this.#table);
		const n1 = new Ciphertext(a1, d1).decrypt(privateKey, this.#table);
		return n0 + n1 * SHIFT_32;
	}
}
