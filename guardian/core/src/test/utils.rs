// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures and client-side sealing helpers shared by Guardian tests.

use anyhow::{anyhow, ensure, Result};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305 as PayloadCipher;
use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{OpModeS, Serializable};
use std::collections::BTreeMap;

use crate::types::{
    EncryptedAmount, EncryptionPublicKey, EncryptionPublicKeyBytes, SealedRequest,
    TransferRecipient, UnsealedRequest, WrappedPayloadKey, MAX_ENCLAVE_KEYS, U16_LIMBS,
};

const HPKE_INFO: &[u8] = b"contra-guardian-request";
const SEALED_REQUEST_VERSION: u8 = 1;

/// Fixed per-limb encryption randomness for tests.
pub const TEST_BLINDINGS: [u64; U16_LIMBS] = [1, 2, 3, 4];

/// Split a u64 into canonical little-endian u16 limbs.
pub(crate) fn plaintext_amount(value: u64) -> [u16; U16_LIMBS] {
    std::array::from_fn(|i| (value >> (16 * i)) as u16)
}

/// Encrypt the canonical little-endian u16 limbs of `value` with the supplied blindings.
pub fn encrypt_amount(value: u64, pk: &PublicKey, blindings: [u64; U16_LIMBS]) -> EncryptedAmount {
    let limbs: [u64; U16_LIMBS] = std::array::from_fn(|i| (value >> (16 * i)) & u16::MAX as u64);
    EncryptedAmount {
        limbs: std::array::from_fn(|i| {
            let blinding = Blinding(RistrettoScalar::from(blindings[i]));
            Ciphertext::new(
                PedersenCommitment::new(&RistrettoScalar::from(limbs[i]), &blinding),
                *pk.as_point() * blinding.0,
            )
        }),
    }
}

/// Collapse deterministic per-limb randomness into one blinding.
pub fn blinding(values: [u64; U16_LIMBS]) -> Blinding {
    let shift = RistrettoScalar::from(1u64 << 16);
    Blinding(
        values
            .into_iter()
            .rev()
            .fold(RistrettoScalar::from(0u64), |sum, value| {
                sum * shift + RistrettoScalar::from(value)
            }),
    )
}

/// Sender (sk 12345) holds 100, sends 40 to one recipient (sk 67890), keeps 60.
pub fn transfer_request() -> UnsealedRequest {
    let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
    let pk_a = PublicKey::from(&x_a);
    let pk_b = PublicKey::from(&PrivateKey::new(RistrettoScalar::from(67890u64)));
    UnsealedRequest::TransferRequest {
        old_encrypted_balance: encrypt_amount(100, &pk_a, TEST_BLINDINGS),
        new_encrypted_balance: encrypt_amount(60, &pk_a, TEST_BLINDINGS),
        recipients: vec![TransferRecipient {
            encrypted_amount: encrypt_amount(40, &pk_b, TEST_BLINDINGS),
            receiver_pk: pk_b,
            amount: plaintext_amount(40),
            blinding: blinding(TEST_BLINDINGS),
        }],
        x_a,
        old_balance: 100,
    }
}

/// BCS-serialize and encrypt a request once, then wrap its payload key for each enclave.
pub fn seal_to_all(
    enc_pks: &[EncryptionPublicKey],
    request: &UnsealedRequest,
) -> Result<SealedRequest> {
    seal_bytes_to_all(enc_pks, &bcs::to_bytes(request)?)
}

pub(crate) fn seal_bytes_to_all(
    enc_pks: &[EncryptionPublicKey],
    plaintext: &[u8],
) -> Result<SealedRequest> {
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
            encrypted_key: wrapped_key
                .try_into()
                .map_err(|_| anyhow!("invalid wrapped payload key length"))?,
        });
    }
    Ok(SealedRequest {
        version: SEALED_REQUEST_VERSION,
        payload_nonce: payload_nonce.into(),
        encrypted_payload,
        wrapped_keys,
    })
}
