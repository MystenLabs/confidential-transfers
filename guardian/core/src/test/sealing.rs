// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{encrypt_amount, transfer_request, TEST_BLINDINGS};
use crate::types::{
    EncryptionPublicKey, EncryptionPublicKeyBytes, SealedRequest, WrappedPayloadKey,
    MAX_ENCLAVE_KEYS, WRAPPED_PAYLOAD_KEY_LENGTH,
};
use crate::{EnclaveKeyPair, GuardianError};
use anyhow::{anyhow, ensure, Result};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305 as PayloadCipher;
use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::twisted_elgamal::{PrivateKey, PublicKey};
use hpke::{OpModeS, Serializable};
use std::collections::BTreeMap;

const PAYLOAD_TAG_LENGTH: usize = 16;

/// BCS-serialize and encrypt a request once, then wrap its payload key for every enclave.
fn seal_to_all(enc_pks: &[EncryptionPublicKey], req: &UnsealedRequest) -> Result<SealedRequest> {
    seal_bytes_to_all(enc_pks, &bcs::to_bytes(req)?)
}

fn seal_bytes_to_all(enc_pks: &[EncryptionPublicKey], plaintext: &[u8]) -> Result<SealedRequest> {
    ensure!(!enc_pks.is_empty(), "no enclave keys to seal to");
    ensure!(
        enc_pks.len() <= MAX_ENCLAVE_KEYS,
        "too many enclave keys: {}; maximum is {MAX_ENCLAVE_KEYS}",
        enc_pks.len()
    );
    let mut rng = rand::thread_rng();
    let payload_key = PayloadCipher::generate_key(&mut rng);
    let payload_nonce = PayloadCipher::generate_nonce(&mut rng);
    let encrypted_payload = PayloadCipher::new(&payload_key)
        .encrypt(
            &payload_nonce,
            Payload {
                msg: plaintext,
                aad: &[SEALED_REQUEST_VERSION],
            },
        )
        .map_err(|e| anyhow!("payload encryption failed: {e}"))?;
    let mut wrapped_keys = BTreeMap::new();
    for pk in enc_pks {
        let enc_pk = EncryptionPublicKeyBytes::from(pk);
        let entry = match wrapped_keys.entry(enc_pk) {
            std::collections::btree_map::Entry::Vacant(entry) => entry,
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(anyhow!("duplicate enclave encryption public key"));
            }
        };
        let (encapped, wrapped_key) =
            hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                pk,
                HPKE_INFO,
                payload_key.as_ref(),
                &[SEALED_REQUEST_VERSION],
                &mut rng,
            )
            .map_err(|e| anyhow!("seal failed: {e}"))?;
        entry.insert(WrappedPayloadKey {
            encapped_key: encapped.to_bytes().into(),
            encrypted_key: wrapped_key.try_into().unwrap(),
        });
    }
    Ok(SealedRequest {
        version: SEALED_REQUEST_VERSION,
        payload_nonce: payload_nonce.into(),
        encrypted_payload,
        wrapped_keys,
    })
}

fn encryption_key(keypair: &EnclaveKeyPair) -> EncryptionPublicKey {
    keypair.enclave_keys().enc_pk.clone()
}

#[test]
fn transfer_and_unwrap_requests_round_trip() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();

    // Transfer sealed to multiple enclaves.
    let request = transfer_request();
    let expected = bcs::to_bytes(&request).unwrap();
    let siblings = [EnclaveKeyPair::generate(), EnclaveKeyPair::generate()];
    let fleet = [
        encryption_key(&keypair),
        encryption_key(&siblings[0]),
        encryption_key(&siblings[1]),
    ];
    let sealed = seal_to_all(&fleet, &request).unwrap();
    assert_eq!(sealed.version, SEALED_REQUEST_VERSION);
    assert_eq!(sealed.wrapped_keys.len(), fleet.len());
    assert_eq!(
        sealed.encrypted_payload.len(),
        expected.len() + PAYLOAD_TAG_LENGTH
    );
    let sealed = bcs::from_bytes(&bcs::to_bytes(&sealed).unwrap()).unwrap();
    let opened = keypair.unseal(&sealed).unwrap();
    assert_eq!(bcs::to_bytes(&opened).unwrap(), expected);
    keypair.verify_and_sign(&opened).unwrap();

    // Unwrap sealed to one enclave.
    let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
    let pk_a = PublicKey::from(&x_a);
    let request = UnsealedRequest::UnwrapRequest {
        old_encrypted_balance: encrypt_amount(100, &pk_a, TEST_BLINDINGS),
        new_encrypted_balance: encrypt_amount(60, &pk_a, TEST_BLINDINGS),
        amount: 40,
        x_a,
        old_balance: 100,
    };
    let expected = bcs::to_bytes(&request).unwrap();
    let sealed = seal_to_all(&[encryption_key(&keypair)], &request).unwrap();
    assert_eq!(sealed.version, SEALED_REQUEST_VERSION);
    assert_eq!(sealed.wrapped_keys.len(), 1);
    assert_eq!(
        sealed.encrypted_payload.len(),
        expected.len() + PAYLOAD_TAG_LENGTH
    );
    let sealed = bcs::from_bytes(&bcs::to_bytes(&sealed).unwrap()).unwrap();
    let opened = keypair.unseal(&sealed).unwrap();
    assert_eq!(bcs::to_bytes(&opened).unwrap(), expected);
    keypair.verify_and_sign(&opened).unwrap();
}

#[test]
fn rejects_unsupported_version() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();
    let mut sealed = seal_to_all(&[encryption_key(&keypair)], &transfer_request()).unwrap();
    sealed.version = SEALED_REQUEST_VERSION + 1;
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::UnsupportedSealedRequestVersion(2))
    );
}

#[test]
fn rejects_empty_wrapped_key_map() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();
    let sealed = SealedRequest {
        version: SEALED_REQUEST_VERSION,
        payload_nonce: [0; 12],
        encrypted_payload: vec![],
        wrapped_keys: BTreeMap::new(),
    };
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::InvalidSealedRequest)
    );
}

#[test]
fn rejects_too_many_wrapped_keys_before_hpke() {
    let sealed = SealedRequest {
        version: SEALED_REQUEST_VERSION,
        payload_nonce: [0; 12],
        encrypted_payload: vec![],
        wrapped_keys: (0..=MAX_ENCLAVE_KEYS as u8)
            .map(|key| {
                (
                    EncryptionPublicKeyBytes::from([key; 32]),
                    WrappedPayloadKey {
                        encapped_key: [0; 32],
                        encrypted_key: [0; WRAPPED_PAYLOAD_KEY_LENGTH],
                    },
                )
            })
            .collect(),
    };
    let keypair = EnclaveKeyPair::from_seed_for_testing();
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::InvalidSealedRequest)
    );
}

#[test]
fn rejects_request_without_its_encryption_public_key() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();
    let sibling = EnclaveKeyPair::generate();
    let sealed = seal_to_all(&[encryption_key(&sibling)], &transfer_request()).unwrap();
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::NotARecipient)
    );
}

#[test]
fn rejects_corrupted_encapsulated_or_encrypted_payload_key() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();
    let enc_pk = EncryptionPublicKeyBytes::from(&keypair.enclave_keys().enc_pk);

    let mut sealed = seal_to_all(&[encryption_key(&keypair)], &transfer_request()).unwrap();
    sealed.wrapped_keys.get_mut(&enc_pk).unwrap().encapped_key[0] ^= 1;
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::NotARecipient)
    );

    let mut sealed = seal_to_all(&[encryption_key(&keypair)], &transfer_request()).unwrap();
    sealed.wrapped_keys.get_mut(&enc_pk).unwrap().encrypted_key[0] ^= 1;
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::NotARecipient)
    );
}

#[test]
fn rejects_corrupted_shared_payload_or_nonce() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();
    let mut sealed = seal_to_all(&[encryption_key(&keypair)], &transfer_request()).unwrap();
    sealed.encrypted_payload[0] ^= 1;
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::InvalidSealedRequest)
    );

    let mut sealed = seal_to_all(&[encryption_key(&keypair)], &transfer_request()).unwrap();
    sealed.payload_nonce[0] ^= 1;
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::InvalidSealedRequest)
    );

    let mut sealed = seal_to_all(&[encryption_key(&keypair)], &transfer_request()).unwrap();
    sealed.encrypted_payload.clear();
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::InvalidSealedRequest)
    );
}

#[test]
fn rejects_malformed_request_bcs() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();
    let sealed = seal_bytes_to_all(&[encryption_key(&keypair)], b"not a bcs request").unwrap();
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::MalformedRequest)
    );
}
