// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { bcs } from '@mysten/sui/bcs';
import { fromHex, toBase64 } from '@mysten/sui/utils';
import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';

import { GuardianClient } from '../../src/guardian.js';
import { G, ZERO } from '../../src/ristretto255.js';
import { Ciphertext, EncryptedAmount } from '../../src/twisted_elgamal.js';
import type { ContraCompatibleClient } from '../../src/types.js';

const TRANSFER_DIGEST = '23c5d517304afc26e1651eae6ed659d8109f14db6565420135ce9ce1ada495a3';
const UNWRAP_DIGEST = 'c7955a80ffafd87ccd7f806ec2e20b80b2a14669cd8d63813d682bcff2856070';

const GuardianState = bcs.struct('Guardian', {
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
				value: bcs.struct('GuardianEnclaveKey', {
					index: bcs.u8(),
					signing_pk: bcs.struct('Ed25519PublicKey', {
						bytes: bcs.vector(bcs.u8()),
					}),
					enc_pk: bcs.struct('X25519PublicKey', { bytes: bcs.vector(bcs.u8()) }),
					version: bcs.u16(),
				}),
			}),
		),
	}),
});

describe('GuardianClient', () => {
	it('matches the Move and Rust transfer and unwrap binding fixtures', async () => {
		const signingSeed = new Uint8Array(32);
		const signingPk = ed25519.getPublicKey(signingSeed);
		const suite = new CipherSuite({
			kem: new DhkemX25519HkdfSha256(),
			kdf: new HkdfSha256(),
			aead: new Chacha20Poly1305(),
		});
		const encryptionKeys = await suite.kem.generateKeyPair();
		const encPk = new Uint8Array(await suite.kem.serializePublicKey(encryptionKeys.publicKey));
		const content = guardianState(signingPk, encPk);
		const signedDigests = [TRANSFER_DIGEST, UNWRAP_DIGEST];
		let requestIndex = 0;
		const guardian = new GuardianClient({
			suiClient: mockClient(content),
			packageId: '0x2',
			guardianId: '0x1',
			fetch: async (_input, init) => {
				expect(init?.method).toBe('POST');
				expect((init?.body as ArrayBuffer).byteLength).toBeGreaterThan(100);
				const digest = fromHex(signedDigests[requestIndex++]);
				const message = bcs
					.struct('GuardianRequest', {
						version: bcs.u16(),
						digest: bcs.vector(bcs.u8()),
					})
					.serialize({ version: 1, digest })
					.toBytes();
				return Response.json({
					signing_pk: toBase64(signingPk),
					signature: toBase64(ed25519.sign(message, signingSeed)),
				});
			},
		});
		const zero = zeroAmount();

		await guardian.approveTransfer({
			senderPk: G,
			oldEncryptedBalance: zero,
			newEncryptedBalance: zero,
			recipients: [
				{
					receiverPk: G,
					encryptedAmount: zero,
					amount: 0n,
					blinding: 0n,
				},
			],
			senderPrivateKey: 1n,
			oldBalance: 0n,
		});
		await guardian.approveUnwrap({
			senderPk: G,
			oldEncryptedBalance: zero,
			newEncryptedBalance: zero,
			amount: 42n,
			senderPrivateKey: 1n,
			oldBalance: 42n,
		});

		expect(requestIndex).toBe(2);
	});

	it('rejects a response from a signing key not registered on chain', async () => {
		const registeredSeed = new Uint8Array(32);
		const responseSeed = new Uint8Array(32).fill(1);
		const suite = new CipherSuite({
			kem: new DhkemX25519HkdfSha256(),
			kdf: new HkdfSha256(),
			aead: new Chacha20Poly1305(),
		});
		const encryptionKeys = await suite.kem.generateKeyPair();
		const encPk = new Uint8Array(await suite.kem.serializePublicKey(encryptionKeys.publicKey));
		const guardian = new GuardianClient({
			suiClient: mockClient(guardianState(ed25519.getPublicKey(registeredSeed), encPk)),
			packageId: '0x2',
			guardianId: '0x1',
			fetch: async () =>
				Response.json({
					signing_pk: toBase64(ed25519.getPublicKey(responseSeed)),
					signature: toBase64(new Uint8Array(64)),
				}),
		});
		const zero = zeroAmount();
		await expect(
			guardian.approveUnwrap({
				senderPk: G,
				oldEncryptedBalance: zero,
				newEncryptedBalance: zero,
				amount: 42n,
				senderPrivateKey: 1n,
				oldBalance: 42n,
			}),
		).rejects.toThrow('unregistered signing key');
	});
});

function zeroAmount(): EncryptedAmount {
	const zero = () => new Ciphertext(ZERO, ZERO);
	return new EncryptedAmount(zero(), zero(), zero(), zero());
}

function guardianState(signingPk: Uint8Array, encPk: Uint8Array): Uint8Array {
	return GuardianState.serialize({
		id: '0x1',
		authority_cap: { authority_id: '0x1' },
		operator: '0x2',
		url: 'http://guardian.test/process_request',
		version: 0,
		min_version: 0,
		pcrs: { pcr0: [], pcr1: [], pcr2: [] },
		guardian_enclave_keys: {
			contents: [
				{
					key: 3,
					value: {
						index: 3,
						signing_pk: { bytes: signingPk },
						enc_pk: { bytes: encPk },
						version: 0,
					},
				},
			],
		},
	}).toBytes();
}

function mockClient(content: Uint8Array): ContraCompatibleClient {
	return {
		core: {
			getObject: async () => ({ object: { content } }),
		},
	} as unknown as ContraCompatibleClient;
}
