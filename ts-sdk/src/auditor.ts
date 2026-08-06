// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { mul, type RistrettoPoint } from './ristretto255.js';
import {
	Ciphertext,
	type DiscreteLogTable,
	type EncryptedAmount,
	type PrivateKey,
} from './twisted_elgamal.js';
import type { ContraAuditorOptions } from './types.js';

/** `2^16`, the base regrouping two u16 limbs into one u32 auditor limb. */
const SHIFT_16 = 1n << 16n;
/** `2^32`, the base combining the two u32 auditor limbs into the u64 amount. */
const SHIFT_32 = 1n << 32n;

/**
 * Per-transfer auditor SDK. Under per-transfer auditing the auditor never learns a user's viewing
 * key; instead every transfer carries auditor-readable ciphertexts of the amount. Given a
 * `TransferEvent`'s `encrypted_amount_receiver` (the receiver's four u16 limbs) and its two
 * `auditor_decryption_handles`, this recovers the transferred amount with the auditor's private key.
 *
 * The two u32-limb commitments are regrouped from the receiver limbs on the fly
 * (`C_0 + 2^16 C_1`, `C_2 + 2^16 C_3`), mirroring on-chain `encrypted_amount::ciphertexts_as_u32_limbs`,
 * and paired with the matching handle to form a twisted ElGamal ciphertext the auditor decrypts.
 */
export class ContraAuditor {
	#tokenType: string;
	#privateKey: PrivateKey;
	#table: DiscreteLogTable;

	constructor(options: ContraAuditorOptions) {
		this.#tokenType = options.tokenType;
		this.#privateKey = options.privateKey;
		this.#table = options.table;
	}

	get tokenType(): string {
		return this.#tokenType;
	}

	/**
	 * Recover the amount of a single transfer from a `TransferEvent`.
	 *
	 * @param encryptedAmountReceiver the event's `encrypted_amount_receiver`, lifted via
	 *   `EncryptedAmount.fromBcs`.
	 * @param auditorHandles the event's two `auditor_decryption_handles` (the `D̃_0`, `D̃_1` for this receiver).
	 * @throws if `auditorHandles` does not have exactly two entries (auditing was disabled for the
	 *   transfer), or if either u32 limb is outside the decryption table's range.
	 */
	decryptTransferAmount(
		encryptedAmountReceiver: EncryptedAmount,
		auditorHandles: readonly RistrettoPoint[],
	): bigint {
		if (auditorHandles.length !== 2) {
			throw new Error(
				`Expected exactly 2 auditor handles, got ${auditorHandles.length}; the transfer carried no auditor data.`,
			);
		}
		const ea = encryptedAmountReceiver;
		const a0 = ea.l0.ciphertext.add(mul(ea.l1.ciphertext, SHIFT_16));
		const a1 = ea.l2.ciphertext.add(mul(ea.l3.ciphertext, SHIFT_16));
		const n0 = new Ciphertext(a0, auditorHandles[0]).decrypt(this.#privateKey, this.#table);
		const n1 = new Ciphertext(a1, auditorHandles[1]).decrypt(this.#privateKey, this.#table);
		return n0 + n1 * SHIFT_32;
	}
}
