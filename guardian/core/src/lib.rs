// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian enclave core.
//!
//! This crate opens requests sealed to an enclave, verifies their plaintext witnesses against the
//! exact encrypted operation, and signs the BCS `GuardianRequest` verified by the Move Guardian.

mod checks;
mod move_types;
mod sealing;
#[cfg(any(test, feature = "test-utils"))]
#[path = "test/utils.rs"]
#[doc(hidden)]
pub mod test_utils;
pub mod types;

use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, Signer};
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
#[cfg(test)]
use rand::{rngs::StdRng, SeedableRng};
use thiserror::Error;

use crate::types::{
    EnclaveKeys, EnclaveResponse, EncryptionPublicKeyBytes, SealedRequest, UnsealedRequest,
};

/// Result type returned by Guardian validation and unsealing operations.
pub type Result<T> = std::result::Result<T, GuardianError>;

/// A request-validation or sealed-transport failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuardianError {
    #[error("transfer has no recipients")]
    EmptyTransfer,
    #[error("transfer has {0} recipients; maximum is 255")]
    TooManyRecipients(usize),
    #[error("not a recipient")]
    NotARecipient,
    #[error("invalid sealed request")]
    InvalidSealedRequest,
    #[error("sealed body is not a BCS UnsealedRequest")]
    MalformedRequest,
    #[error("unsupported sealed-request version {0}")]
    UnsupportedSealedRequestVersion(u8),
    #[error("balance does not open to the expected value")]
    BalanceMismatch,
    #[error("encrypted amount mismatch at recipient {recipient}")]
    RecipientAmountMismatch { recipient: usize },
    #[error("total transfer amount exceeds u64")]
    TransferAmountOverflow,
    #[error("transfer exceeds the sender's balance")]
    Overdraft,
}

/// An enclave's Ed25519 signing and X25519 HPKE key pairs, with their public keys cached.
pub struct EnclaveKeyPair {
    signing_sk: Ed25519KeyPair,
    hpke_sk: <X25519HkdfSha256 as Kem>::PrivateKey,
    enclave_keys: EnclaveKeys,
}

impl EnclaveKeyPair {
    /// Generate fresh keys from the operating system RNG at boot.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let (hpke_sk, hpke_pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let signing_sk = Ed25519KeyPair::generate(&mut rng);
        let enclave_keys = EnclaveKeys {
            signing_pk: signing_sk.public().clone(),
            enc_pk: hpke_pk,
        };
        Self {
            signing_sk,
            hpke_sk,
            enclave_keys,
        }
    }

    /// Deterministic test keys generated sequentially from an all-zero RNG seed.
    #[cfg(test)]
    fn from_seed_for_testing() -> Self {
        let mut rng = StdRng::from_seed([0; 32]);
        let (hpke_sk, hpke_pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let signing_sk = Ed25519KeyPair::generate(&mut rng);
        let enclave_keys = EnclaveKeys {
            signing_pk: signing_sk.public().clone(),
            enc_pk: hpke_pk,
        };
        Self {
            signing_sk,
            hpke_sk,
            enclave_keys,
        }
    }

    /// Return the public keys encoded into attestation `user_data` and parsed by
    /// `guardian::parse_user_data` on chain.
    pub fn enclave_keys(&self) -> &EnclaveKeys {
        &self.enclave_keys
    }

    /// Decrypt a request sealed to this enclave. Each request carries a wrapped payload key for
    /// every live enclave, so the proxy can load-balance without key-aware routing.
    pub fn unseal(&self, request: &SealedRequest) -> Result<UnsealedRequest> {
        let enc_pk = EncryptionPublicKeyBytes::from(&self.enclave_keys.enc_pk);
        sealing::unseal(&self.hpke_sk, enc_pk, request)
    }

    /// Verify the plaintext witnesses and sign the resulting BCS `GuardianRequest`.
    pub fn verify_and_sign(&self, req: &UnsealedRequest) -> Result<EnclaveResponse> {
        let request = checks::verified_request_bytes(req)?;
        Ok(EnclaveResponse {
            signing_pk: self.signing_sk.public().clone(),
            signature: self.signing_sk.sign(&request),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{blinding, encrypt_amount};
    use crate::types::{Recipient, UnsealedRequest};
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::ristretto255::RistrettoScalar;
    use fastcrypto::twisted_elgamal::{PrivateKey, PublicKey};

    // Must match the signature fixture used by Move test
    // `guardian_e2e_tests::guardian_valid_sig_transfer_passes`.
    #[test]
    fn transfer_signature_matches_move_fixture() {
        // Sender sk 12345 holding 100 sends 50 to receiver sk 67890, with limb-0 blindings
        // r_xfer=32533 and r_balance=10097.
        let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
        let pk_a = PublicKey::from(&x_a);
        let pk_b = PublicKey::from(&PrivateKey::new(RistrettoScalar::from(67890u64)));
        let keypair = EnclaveKeyPair::from_seed_for_testing();

        let req = UnsealedRequest::TransferRequest {
            old_encrypted_balance: encrypt_amount(100, &pk_a, [0, 0, 0, 0]),
            new_encrypted_balance: encrypt_amount(50, &pk_a, [10097, 0, 0, 0]),
            recipients: vec![Recipient {
                encrypted_amount: encrypt_amount(50, &pk_b, [32533, 0, 0, 0]),
                receiver_pk: pk_b,
                amount: 50,
                blinding: blinding([32533, 0, 0, 0]),
            }],
            x_a,
            old_balance: 100,
        };

        let EnclaveResponse {
            signing_pk,
            signature,
        } = keypair
            .verify_and_sign(&req)
            .expect("valid request must be signed");
        assert_eq!(
            Hex::encode(signature.as_ref()),
            "663dee617bacd7dac45afb4b1e0f5abe689ecfad9ec841a258daf7d3bc25a6f149e9d29ae2c61965dc030358d69b1699d5fb46c010f6fc81bdd8b40914009d0b"
        );
        assert_eq!(
            Hex::encode(signing_pk.as_ref()),
            "aef3f4a4b8eca1dfc343361bf8e436bd42de9259c04b8314eb8e2054dd6e82ab"
        );
        assert_eq!(signing_pk, keypair.enclave_keys().signing_pk);
    }

    // Must match the signature fixture used by Move test
    // `guardian_e2e_tests::guardian_valid_sig_unwrap_passes`.
    #[test]
    fn unwrap_signature_matches_move_fixture() {
        let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
        let pk_a = PublicKey::from(&x_a);
        let keypair = EnclaveKeyPair::from_seed_for_testing();

        let req = UnsealedRequest::UnwrapRequest {
            old_encrypted_balance: encrypt_amount(100, &pk_a, [0, 0, 0, 0]),
            new_encrypted_balance: encrypt_amount(60, &pk_a, [76520, 0, 0, 0]),
            amount: 40,
            x_a,
            old_balance: 100,
        };

        let response = keypair
            .verify_and_sign(&req)
            .expect("valid request must be signed");
        assert_eq!(
            Hex::encode(response.signature.as_ref()),
            "91797d0f540182a08e3145fe7d3b24b5709950dce566a922952726378f4de25d80dd1e108b3209a60067cb6d4082d962f7c55b6fc3c0a3c5e2d198ef02cda50a"
        );
    }

    #[test]
    fn refuses_with_the_failed_checks_reason() {
        let keypair = EnclaveKeyPair::from_seed_for_testing();
        let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
        // Claims 200 while the encrypted balance encodes 100.
        let req = UnsealedRequest::UnwrapRequest {
            old_encrypted_balance: encrypt_amount(100, &PublicKey::from(&x_a), [0, 0, 0, 0]),
            new_encrypted_balance: encrypt_amount(60, &PublicKey::from(&x_a), [0, 0, 0, 0]),
            amount: 40,
            x_a,
            old_balance: 200,
        };
        let error = keypair
            .verify_and_sign(&req)
            .expect_err("bad request must be refused");
        assert_eq!(error, GuardianError::BalanceMismatch);
        assert_eq!(
            error.to_string(),
            "balance does not open to the expected value"
        );
    }
}
