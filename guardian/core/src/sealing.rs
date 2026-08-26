// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Envelope encryption for client-to-enclave requests.
//!
//! The client encrypts the BCS request once under a random ChaCha20-Poly1305 payload key. For each
//! enclave, it then uses HPKE to produce a KEM encapsulation and an encrypted copy of that payload
//! key. An enclave selects its entry by encryption public key, opens the payload key, and decrypts
//! the shared request.

use crate::types::{EncryptionPublicKeyBytes, SealedRequest, UnsealedRequest, MAX_ENCLAVE_KEYS};
use crate::GuardianError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305 as PayloadCipher, Nonce};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR};

/// Binds HPKE ciphertexts to requests encrypted for Guardian enclaves.
const HPKE_INFO: &[u8] = b"contra-guardian-request";
/// Version for the client-to-enclave sealed request.
const SEALED_REQUEST_VERSION: u8 = 1;

type PrivateKey = <X25519HkdfSha256 as Kem>::PrivateKey;
type EncappedKey = <X25519HkdfSha256 as Kem>::EncappedKey;

/// Validate the envelope, open the payload key wrapped for `enc_pk`, decrypt the shared payload,
/// and BCS-decode its request.
pub(super) fn unseal(
    sk: &PrivateKey,
    enc_pk: EncryptionPublicKeyBytes,
    request: &SealedRequest,
) -> crate::Result<UnsealedRequest> {
    if request.version != SEALED_REQUEST_VERSION {
        return Err(GuardianError::UnsupportedSealedRequestVersion(
            request.version,
        ));
    }
    if request.wrapped_keys.is_empty() || request.wrapped_keys.len() > MAX_ENCLAVE_KEYS {
        return Err(GuardianError::InvalidSealedRequest);
    }

    // Select this enclave's wrapped payload key.
    let wrapped = request
        .wrapped_keys
        .get(&enc_pk)
        .ok_or(GuardianError::NotARecipient)?;
    let encapped =
        EncappedKey::from_bytes(&wrapped.encapped_key).expect("32-byte X25519 public key");

    // Open the payload key with this enclave's HPKE private key.
    let payload_key = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        sk,
        &encapped,
        HPKE_INFO,
        &wrapped.encrypted_key,
        &[request.version],
    )
    .map_err(|_| GuardianError::PayloadKeyUnwrapFailed)?;

    // Decrypt and authenticate the shared request.
    let cipher = PayloadCipher::new_from_slice(&payload_key)
        .map_err(|_| GuardianError::InvalidSealedRequest)?;
    let nonce = Nonce::from(request.payload_nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &request.encrypted_payload,
                aad: &[request.version],
            },
        )
        .map_err(|_| GuardianError::InvalidSealedRequest)?;
    bcs::from_bytes(&plaintext).map_err(|_| GuardianError::MalformedRequest)
}

#[cfg(test)]
#[path = "test/sealing.rs"]
mod tests;
