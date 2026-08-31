// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{
    encrypt_amount, seal_bytes_to_all, seal_to_all, transfer_request, TEST_BLINDINGS,
};
use crate::types::{
    EncryptionPublicKey, EncryptionPublicKeyBytes, SealedRequest, WrappedPayloadKey,
    MAX_ENCLAVE_KEYS, WRAPPED_PAYLOAD_KEY_LENGTH,
};
use crate::{EnclaveKeyPair, GuardianError};
use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::twisted_elgamal::{PrivateKey, PublicKey};
use std::collections::BTreeMap;

const PAYLOAD_TAG_LENGTH: usize = 16;

fn encryption_key(keypair: &EnclaveKeyPair) -> EncryptionPublicKey {
    keypair.enclave_keys().enc_pk.clone()
}

#[test]
fn transfer_and_unwrap_requests_round_trip() {
    let keypair = EnclaveKeyPair::from_seed_for_testing();

    // Transfer sealed to multiple enclaves.
    let request = transfer_request();
    let expected = bcs::to_bytes(&request).unwrap();
    let mut rng = rand::thread_rng();
    let siblings = [
        EnclaveKeyPair::generate(&mut rng),
        EnclaveKeyPair::generate(&mut rng),
    ];
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
    let sibling = EnclaveKeyPair::generate(&mut rand::thread_rng());
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
        Some(GuardianError::PayloadKeyUnwrapFailed)
    );

    let mut sealed = seal_to_all(&[encryption_key(&keypair)], &transfer_request()).unwrap();
    sealed.wrapped_keys.get_mut(&enc_pk).unwrap().encrypted_key[0] ^= 1;
    assert_eq!(
        keypair.unseal(&sealed).err(),
        Some(GuardianError::PayloadKeyUnwrapFailed)
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
