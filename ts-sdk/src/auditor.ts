// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { AuditorKeyNotHeldError } from './error.js';
import { G, mul, pointFromBcs, type RistrettoPoint } from './ristretto255.js';
import {
	Ciphertext,
	EncryptedAmount,
	type DiscreteLogTable,
	type PrivateKey,
} from './twisted_elgamal.js';
import type { ContraAuditorOptions } from './types.js';

const SHIFT_16 = 1n << 16n;
const SHIFT_32 = 1n << 32n;

/**
 * The decoded `TransferEvent` fields an auditor reads (`events.ts` `TransferEvent`, via
 * `TransferEventBcs.parse`). A full decoded event is structurally assignable.
 */
export type DecodedTransferEvent = {
	encrypted_amount_receiver: Parameters<typeof EncryptedAmount.fromBcs>[0];
	auditor_decryption_handles: { handles: { bytes: number[] }[] } | null;
	auditor_pk: { element: { bytes: number[] } } | null;
};

/**
 * Per-transfer auditor SDK. Under per-transfer auditing the auditor never learns a user's viewing
 * key; instead every transfer carries auditor-readable ciphertexts of the amount. Given a
 * `TransferEvent`'s `encrypted_amount_receiver` (the receiver's four u16 limbs) and its two
 * `auditor_decryption_handles`, this recovers the transferred amount with the auditor's private key.
 *
 * The two u32-limb commitments are regrouped from the receiver limbs on the fly
 * (`C_0 + 2^16 C_1`, `C_2 + 2^16 C_3`), mirroring on-chain `encrypted_amount::ciphertexts_as_u32_limbs`,
 * and paired with the matching handle to form a twisted ElGamal ciphertext the auditor decrypts.
 *
 * An auditor holds one or more private keys. A token's auditor key can be rotated, and a transfer
 * made before a rotation stays encrypted under whichever key was current then (accepted on chain
 * during the grace window, and readable off-chain forever). To decrypt across rotations, construct
 * the auditor with every key it has ever held — or add rotated-out keys later with `addKey` —
 * and `decryptTransferAmount` selects the private key whose public key (`pk = sk * G`) matches the
 * transfer's `auditor_pk`.
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
	 * Recover the transferred amount from a `TransferEvent`, using the held key whose public key
	 * matches the event's `auditor_pk`. Regroups the receiver's four u16 limbs into the two u32-limb
	 * commitments (`C_0 + 2^16 C_1`, `C_2 + 2^16 C_3`, mirroring on-chain
	 * `encrypted_amount::ciphertexts_as_u32_limbs`), pairs each with the matching handle, and
	 * BSGS-decrypts.
	 *
	 * @param event a decoded `TransferEvent` (`TransferEventBcs.parse`).
	 * @returns the transferred amount, or `null` if the transfer carried no auditor data (auditing was
	 *   disabled for it).
	 * @throws {@link AuditorKeyNotHeldError} if this auditor holds no key matching the event's
	 *   `auditor_pk`; {@link DecryptionFailedError} if a u32 limb is outside the decryption table's range.
	 */
	decryptTransferAmount(event: DecodedTransferEvent): bigint | null {
		const handles = event.auditor_decryption_handles;
		if (event.auditor_pk === null || handles === null || handles.handles.length !== 2) return null;
		const auditorPk = pointFromBcs(event.auditor_pk.element);
		const privateKey = this.#keys.find((k) => k.publicKey.equals(auditorPk))?.privateKey;
		if (privateKey === undefined) {
			throw new AuditorKeyNotHeldError(auditorPk);
		}
		const ea = EncryptedAmount.fromBcs(event.encrypted_amount_receiver);
		const [d0, d1] = handles.handles.map((h) => pointFromBcs(h));
		const a0 = ea.l0.ciphertext.add(mul(ea.l1.ciphertext, SHIFT_16));
		const a1 = ea.l2.ciphertext.add(mul(ea.l3.ciphertext, SHIFT_16));
		const n0 = new Ciphertext(a0, d0).decrypt(privateKey, this.#table);
		const n1 = new Ciphertext(a1, d1).decrypt(privateKey, this.#table);
		return n0 + n1 * SHIFT_32;
	}
}
