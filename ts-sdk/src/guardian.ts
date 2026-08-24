// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { bcs } from '@mysten/sui/bcs';
import type { Transaction, TransactionResult } from '@mysten/sui/transactions';
import { fromBase64 } from '@mysten/sui/utils';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';

import { scalarToBytes, type RistrettoPoint } from './ristretto255.js';
import type { EncryptedAmount } from './twisted_elgamal.js';
import type { ContraCompatibleClient } from './types.js';

const REQUEST_VERSION = 1;
const SEALED_REQUEST_VERSION = 1;
const MAX_ENCLAVE_KEYS = 16;
const HPKE_INFO = new TextEncoder().encode('contra-guardian-request');
const HPKE_SUITE = new CipherSuite({
	kem: new DhkemX25519HkdfSha256(),
	kdf: new HkdfSha256(),
	aead: new Chacha20Poly1305(),
});

const Bytes32 = bcs.fixedArray(32, bcs.u8());
const MoveElement = bcs.struct('MoveElement', { bytes: bcs.vector(bcs.u8()) });
const MoveEncryption = bcs.struct('MoveEncryption', {
	ciphertext: MoveElement,
	decryption_handle: MoveElement,
});
const MoveEncryptedAmount = bcs.struct('MoveEncryptedAmount', {
	l0: MoveEncryption,
	l1: MoveEncryption,
	l2: MoveEncryption,
	l3: MoveEncryption,
});
const MoveBinding = bcs.enum('Binding', {
	Transfer: bcs.struct('TransferBinding', {
		sender_pk: MoveElement,
		receiver_pks: bcs.vector(MoveElement),
		old_encrypted_balance: MoveEncryptedAmount,
		new_encrypted_balance: MoveEncryptedAmount,
		encrypted_amounts: bcs.vector(MoveEncryptedAmount),
	}),
	Unwrap: bcs.struct('UnwrapBinding', {
		sender_pk: MoveElement,
		old_encrypted_balance: MoveEncryptedAmount,
		new_encrypted_balance: MoveEncryptedAmount,
		amount: bcs.u64(),
	}),
});

const WireRecipient = bcs.struct('Recipient', {
	receiver_pk: Bytes32,
	encrypted_amount: MoveEncryptedAmount,
	amount: bcs.u64(),
	blinding: Bytes32,
});
const UnsealedRequest = bcs.enum('UnsealedRequest', {
	TransferRequest: bcs.struct('TransferRequest', {
		old_encrypted_balance: MoveEncryptedAmount,
		new_encrypted_balance: MoveEncryptedAmount,
		recipients: bcs.vector(WireRecipient),
		x_a: Bytes32,
		old_balance: bcs.u64(),
	}),
	UnwrapRequest: bcs.struct('UnwrapRequest', {
		old_encrypted_balance: MoveEncryptedAmount,
		new_encrypted_balance: MoveEncryptedAmount,
		amount: bcs.u64(),
		x_a: Bytes32,
		old_balance: bcs.u64(),
	}),
});
const WrappedPayloadKey = bcs.struct('WrappedPayloadKey', {
	encapped_key: Bytes32,
	encrypted_key: bcs.fixedArray(48, bcs.u8()),
});
const SealedRequest = bcs.struct('SealedRequest', {
	version: bcs.u8(),
	payload_nonce: bcs.fixedArray(12, bcs.u8()),
	encrypted_payload: bcs.vector(bcs.u8()),
	wrapped_keys: bcs.map(Bytes32, WrappedPayloadKey),
});
const GuardianRequest = bcs.struct('GuardianRequest', {
	version: bcs.u16(),
	digest: bcs.vector(bcs.u8()),
});

const GuardianEnclaveKey = bcs.struct('GuardianEnclaveKey', {
	index: bcs.u8(),
	signing_pk: bcs.struct('Ed25519PublicKey', { bytes: bcs.vector(bcs.u8()) }),
	enc_pk: bcs.struct('X25519PublicKey', { bytes: bcs.vector(bcs.u8()) }),
	version: bcs.u16(),
});
const Guardian = bcs.struct('Guardian', {
	id: bcs.Address,
	authority_cap: bcs.struct('AuthorityCap', { authority_id: bcs.Address }),
	operator: bcs.Address,
	url: bcs.string(),
	version: bcs.u16(),
	min_version: bcs.u16(),
	pcrs: bcs.struct('Pcrs', {
		pcr0: bcs.vector(bcs.u8()),
		pcr1: bcs.vector(bcs.u8()),
		pcr2: bcs.vector(bcs.u8()),
	}),
	guardian_enclave_keys: bcs.struct('GuardianEnclaveKeys', {
		contents: bcs.vector(
			bcs.struct('GuardianEnclaveKeyEntry', {
				key: bcs.u8(),
				value: GuardianEnclaveKey,
			}),
		),
	}),
});

export interface GuardianClientOptions {
	suiClient: ContraCompatibleClient;
	/** Published Guardian package containing `guardian::guardian`. */
	packageId: string;
	/** Guardian object enabled for the token. */
	guardianId: string;
	/** Optional URL override; otherwise the current URL is read from the Guardian object. */
	url?: string;
	/** Optional fetch implementation for non-browser runtimes and tests. */
	fetch?: typeof fetch;
}

export interface GuardianTransferRecipient {
	receiverPk: RistrettoPoint;
	encryptedAmount: EncryptedAmount;
	amount: bigint;
	blinding: bigint;
}

export interface GuardianTransferRequest {
	senderPk: RistrettoPoint;
	oldEncryptedBalance: EncryptedAmount;
	newEncryptedBalance: EncryptedAmount;
	recipients: readonly GuardianTransferRecipient[];
	senderPrivateKey: bigint;
	oldBalance: bigint;
}

export interface GuardianUnwrapRequest {
	senderPk: RistrettoPoint;
	oldEncryptedBalance: EncryptedAmount;
	newEncryptedBalance: EncryptedAmount;
	amount: bigint;
	senderPrivateKey: bigint;
	oldBalance: bigint;
}

interface EnclaveResponse {
	signing_pk: string;
	signature: string;
}

interface PreparedRequest {
	digest: Uint8Array;
	plaintext: Uint8Array;
}

/** A verified enclave response ready to mint the corresponding on-chain approval. */
export class GuardianApproval {
	readonly #guardianPackageId: string;
	readonly #guardianId: string;
	readonly #keyIndex: number;
	readonly #signature: Uint8Array;
	readonly #digest: Uint8Array;

	constructor(
		guardianPackageId: string,
		guardianId: string,
		keyIndex: number,
		signature: Uint8Array,
		digest: Uint8Array,
	) {
		this.#guardianPackageId = guardianPackageId;
		this.#guardianId = guardianId;
		this.#keyIndex = keyIndex;
		this.#signature = signature;
		this.#digest = digest;
	}

	/** Add `guardian::new_approval` and return its `Option<Approval<T>>`. */
	addToTransaction(
		tx: Transaction,
		tokenType: string,
		confidentialTokenId: string,
	): TransactionResult {
		const [signature] = tx.moveCall({
			target: `${this.#guardianPackageId}::guardian::new_guardian_signature`,
			arguments: [tx.pure.u8(this.#keyIndex), tx.pure.vector('u8', this.#signature)],
		});
		return tx.moveCall({
			target: `${this.#guardianPackageId}::guardian::new_approval`,
			typeArguments: [tokenType],
			arguments: [
				tx.object(this.#guardianId),
				tx.object(confidentialTokenId),
				tx.pure.vector('u8', this.#digest),
				signature,
			],
		});
	}
}

/** Client for obtaining Guardian approvals for Contra operations. */
export class GuardianClient {
	readonly #suiClient: ContraCompatibleClient;
	readonly #packageId: string;
	readonly #guardianId: string;
	readonly #url?: string;
	readonly #fetch: typeof fetch;

	constructor(options: GuardianClientOptions) {
		this.#suiClient = options.suiClient;
		this.#packageId = options.packageId;
		this.#guardianId = options.guardianId;
		this.#url = options.url;
		this.#fetch = options.fetch ?? globalThis.fetch;
		if (!this.#fetch) throw new Error('GuardianClient requires a fetch implementation');
	}

	async approveTransfer(request: GuardianTransferRequest): Promise<GuardianApproval> {
		const oldEncryptedBalance = encryptedAmount(request.oldEncryptedBalance);
		const newEncryptedBalance = encryptedAmount(request.newEncryptedBalance);
		const recipients = request.recipients.map((recipient) => ({
			receiver_pk: Array.from(recipient.receiverPk.toBytes()),
			encrypted_amount: encryptedAmount(recipient.encryptedAmount),
			amount: recipient.amount,
			blinding: Array.from(scalarToBytes(recipient.blinding)),
		}));
		const binding = MoveBinding.serialize({
			Transfer: {
				sender_pk: moveElement(request.senderPk),
				receiver_pks: request.recipients.map((recipient) => moveElement(recipient.receiverPk)),
				old_encrypted_balance: oldEncryptedBalance,
				new_encrypted_balance: newEncryptedBalance,
				encrypted_amounts: recipients.map(({ encrypted_amount }) => encrypted_amount),
			},
		}).toBytes();
		return this.#approve({
			digest: blake2b(binding, { dkLen: 32 }),
			plaintext: UnsealedRequest.serialize({
				TransferRequest: {
					old_encrypted_balance: oldEncryptedBalance,
					new_encrypted_balance: newEncryptedBalance,
					recipients,
					x_a: Array.from(scalarToBytes(request.senderPrivateKey)),
					old_balance: request.oldBalance,
				},
			}).toBytes(),
		});
	}

	async approveUnwrap(request: GuardianUnwrapRequest): Promise<GuardianApproval> {
		const oldEncryptedBalance = encryptedAmount(request.oldEncryptedBalance);
		const newEncryptedBalance = encryptedAmount(request.newEncryptedBalance);
		const binding = MoveBinding.serialize({
			Unwrap: {
				sender_pk: moveElement(request.senderPk),
				old_encrypted_balance: oldEncryptedBalance,
				new_encrypted_balance: newEncryptedBalance,
				amount: request.amount,
			},
		}).toBytes();
		return this.#approve({
			digest: blake2b(binding, { dkLen: 32 }),
			plaintext: UnsealedRequest.serialize({
				UnwrapRequest: {
					old_encrypted_balance: oldEncryptedBalance,
					new_encrypted_balance: newEncryptedBalance,
					amount: request.amount,
					x_a: Array.from(scalarToBytes(request.senderPrivateKey)),
					old_balance: request.oldBalance,
				},
			}).toBytes(),
		});
	}

	async #approve(request: PreparedRequest): Promise<GuardianApproval> {
		const { object } = await this.#suiClient.core.getObject({
			objectId: this.#guardianId,
			include: { content: true },
		});
		const guardian = Guardian.parse(object.content);
		const keys = guardian.guardian_enclave_keys.contents.map(({ key, value }) => {
			if (key !== value.index) throw new Error(`Guardian enclave key index mismatch at ${key}`);
			return {
				index: key,
				signingPk: Uint8Array.from(value.signing_pk.bytes),
				encPk: Uint8Array.from(value.enc_pk.bytes),
			};
		});
		if (keys.length === 0) throw new Error('Guardian has no registered enclave keys');
		if (keys.length > MAX_ENCLAVE_KEYS) throw new Error('Guardian has too many enclave keys');

		const body = await seal(
			request.plaintext,
			keys.map(({ encPk }) => encPk),
		);
		const response = await this.#fetch(this.#url ?? guardian.url, {
			method: 'POST',
			headers: { 'content-type': 'application/octet-stream' },
			body: body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
		});
		if (!response.ok) {
			throw new Error(`Guardian request failed (${response.status}): ${await response.text()}`);
		}
		const json = (await response.json()) as EnclaveResponse;
		const signingPk = fromBase64(json.signing_pk);
		const signature = fromBase64(json.signature);
		if (signingPk.length !== 32 || signature.length !== 64) {
			throw new Error('Guardian response has invalid key or signature length');
		}
		const key = keys.find(({ signingPk: registered }) => equalBytes(registered, signingPk));
		if (!key) throw new Error('Guardian response used an unregistered signing key');

		const signedRequest = GuardianRequest.serialize({
			version: REQUEST_VERSION,
			digest: request.digest,
		}).toBytes();
		if (!ed25519.verify(signature, signedRequest, signingPk)) {
			throw new Error('Guardian response signature is invalid');
		}
		return new GuardianApproval(
			this.#packageId,
			this.#guardianId,
			key.index,
			signature,
			request.digest,
		);
	}
}

function moveElement(point: RistrettoPoint) {
	return { bytes: Array.from(point.toBytes()) };
}

function encryptedAmount(amount: EncryptedAmount) {
	const [l0, l1, l2, l3] = amount.limbs.map((limb) => ({
		ciphertext: moveElement(limb.ciphertext),
		decryption_handle: moveElement(limb.decryptionHandle),
	}));
	return { l0, l1, l2, l3 };
}

async function seal(plaintext: Uint8Array, encPks: readonly Uint8Array[]): Promise<Uint8Array> {
	const payloadKey = randomBytes(32);
	const payloadNonce = randomBytes(12);
	const aad = Uint8Array.of(SEALED_REQUEST_VERSION);
	const encryptedPayload = chacha20poly1305(payloadKey, payloadNonce, aad).encrypt(plaintext);
	const wrapped = await Promise.all(
		encPks.map(async (encPk) => {
			if (encPk.length !== 32) throw new Error('Guardian encryption key must be 32 bytes');
			const recipientPublicKey = await HPKE_SUITE.kem.importKey(
				'raw',
				encPk.buffer.slice(encPk.byteOffset, encPk.byteOffset + encPk.byteLength) as ArrayBuffer,
				true,
			);
			const { enc, ct } = await HPKE_SUITE.seal(
				{ recipientPublicKey, info: HPKE_INFO },
				payloadKey,
				aad,
			);
			return {
				encPk,
				value: {
					encapped_key: Array.from(new Uint8Array(enc)),
					encrypted_key: Array.from(new Uint8Array(ct)),
				},
			};
		}),
	);
	wrapped.sort((a, b) => compareBytes(a.encPk, b.encPk));
	const wrappedKeys = new Map(wrapped.map(({ encPk, value }) => [Array.from(encPk), value]));
	return SealedRequest.serialize({
		version: SEALED_REQUEST_VERSION,
		payload_nonce: Array.from(payloadNonce),
		encrypted_payload: encryptedPayload,
		wrapped_keys: wrappedKeys,
	}).toBytes();
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return a[i] - b[i];
	}
	return 0;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
	return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
