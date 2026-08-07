// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian second factor: re-checks confidential transfer arithmetic in plaintext and
//! signs a response the chain verifies against a registered enclave key (design:
//! `guardian/README.md`).

pub(crate) mod checks;
pub mod sealing;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod types;

use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, Signer};
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem, Serializable};
#[cfg(any(test, feature = "testing"))]
use rand::{rngs::StdRng, SeedableRng};
use thiserror::Error;

use crate::types::{EnclaveKeys, EnclaveResponse, UnsealedRequest};

pub type Result<T> = std::result::Result<T, GuardianError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuardianError {
    #[error("transfer has no recipients")]
    EmptyTransfer,
    #[error("not a recipient")]
    NotARecipient,
    #[error("sealed body is not a BCS UnsealedRequest")]
    MalformedRequest,
    #[error("old balance does not open to the claimed value")]
    OldBalanceMismatch,
    #[error("new balance does not open to the implied value")]
    NewBalanceMismatch,
    #[error("recipient amount {0} is not a well-formed encryption")]
    AmountMismatch(usize),
    #[error("transfer exceeds the sender's balance")]
    Overdraft,
}

/// An enclave's signing key and encryption key, with the public halves cached.
pub struct EnclaveKeyPair {
    signing_sk: Ed25519KeyPair,
    hpke_sk: <X25519HkdfSha256 as Kem>::PrivateKey,
    keys: EnclaveKeys,
}

impl EnclaveKeyPair {
    /// Generate fresh keys at boot.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let (hpke_sk, hpke_pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let signing_sk = Ed25519KeyPair::generate(&mut rng);
        let keys = EnclaveKeys {
            signing_pk: signing_sk.public().clone(),
            enc_pk: hpke_pk.to_bytes().into(),
        };
        Self {
            signing_sk,
            hpke_sk,
            keys,
        }
    }

    /// Deterministic keys for tests, derived from an all-zero seed.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_seed_for_testing() -> Self {
        let mut rng = StdRng::from_seed([0; 32]);
        let (hpke_sk, hpke_pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let signing_sk = Ed25519KeyPair::generate(&mut rng);
        let keys = EnclaveKeys {
            signing_pk: signing_sk.public().clone(),
            enc_pk: hpke_pk.to_bytes().into(),
        };
        Self {
            signing_sk,
            hpke_sk,
            keys,
        }
    }

    /// The public keys to embed in the attestation's `user_data`, laid out as
    /// `guardian::parse_user_data` expects.
    pub fn keys(&self) -> &EnclaveKeys {
        &self.keys
    }

    /// Open whichever envelope is addressed to this instance and decode the request.
    pub fn unseal(&self, envelopes: &[sealing::SealedEnvelope]) -> Result<UnsealedRequest> {
        for envelope in envelopes {
            match sealing::open(&self.hpke_sk, envelope) {
                Err(GuardianError::NotARecipient) => continue,
                result => return result,
            }
        }
        Err(GuardianError::NotARecipient)
    }

    /// Verify the request and sign the payload.
    pub fn verify_and_sign(&self, req: &UnsealedRequest) -> Result<EnclaveResponse> {
        let payload = checks::verify_payload(req)?;
        Ok(EnclaveResponse {
            signing_pk: self.signing_sk.public().clone(),
            signature: self.signing_sk.sign(&payload.to_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::{Recipient, UnsealedRequest};
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use fastcrypto::groups::GroupElement;
    use fastcrypto::pedersen::{Blinding, PedersenCommitment, H};
    use fastcrypto::traits::ToFromBytes;
    use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};

    #[test]
    fn transfer_signature_matches_move_fixture() {
        // Sender sk 12345 holding 100 sends 50 to receiver sk 67890, with limb-0 blindings
        // r_xfer=32533 and r_balance=10097.
        let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
        let pk_a = PublicKey::from(&x_a);
        let pk_b = PublicKey::from(&PrivateKey::new(RistrettoScalar::from(67890u64)));
        let seed: Vec<u8> = (0u8..32).collect();
        let mut keypair = EnclaveKeyPair::from_seed_for_testing();
        keypair.signing_sk = Ed25519KeyPair::from_bytes(&seed).unwrap();

        let req = UnsealedRequest::TransferRequest {
            old_encrypted_balance: Ciphertext::new(
                PedersenCommitment(*H * RistrettoScalar::from(100u64)),
                RistrettoPoint::zero(),
            ),
            new_encrypted_balance: Ciphertext::new(
                PedersenCommitment::new(
                    &RistrettoScalar::from(50u64),
                    &Blinding(RistrettoScalar::from(10097u64)),
                ),
                *pk_a.as_point() * RistrettoScalar::from(10097u64),
            ),
            recipients: vec![Recipient {
                receiver_pk: pk_b.clone(),
                encrypted_amount: Ciphertext::new(
                    PedersenCommitment::new(
                        &RistrettoScalar::from(50u64),
                        &Blinding(RistrettoScalar::from(32533u64)),
                    ),
                    *pk_b.as_point() * RistrettoScalar::from(32533u64),
                ),
                amount: 50,
                blinding: Blinding(RistrettoScalar::from(32533u64)),
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
            "7118ad4962063ce9f9bd3460ab0d361ec7ae3ade7571089c93ed0d5d6794ac3baec5c3546d4209bdfcf2c666cd4a36ac1b74a7e6f17ecbf99142380ad940c700"
        );
        assert_eq!(
            Hex::encode(signing_pk.as_ref()),
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
        );
    }

    /// A refused request answers with the failed check's message rather than a signature.
    #[test]
    fn refuses_with_the_failed_checks_reason() {
        let seed: Vec<u8> = (0u8..32).collect();
        let mut keypair = EnclaveKeyPair::from_seed_for_testing();
        keypair.signing_sk = Ed25519KeyPair::from_bytes(&seed).unwrap();
        let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
        // Claims 200 while the balance ciphertext encrypts 100.
        let req = UnsealedRequest::UnwrapRequest {
            old_encrypted_balance: Ciphertext::new(
                PedersenCommitment(*H * RistrettoScalar::from(100u64)),
                RistrettoPoint::zero(),
            ),
            new_encrypted_balance: Ciphertext::new(
                PedersenCommitment(*H * RistrettoScalar::from(60u64)),
                RistrettoPoint::zero(),
            ),
            amount: 40,
            x_a,
            old_balance: 200,
        };
        let error = keypair
            .verify_and_sign(&req)
            .expect_err("bad request must be refused");
        assert_eq!(error, GuardianError::OldBalanceMismatch);
        assert_eq!(
            error.to_string(),
            "old balance does not open to the claimed value"
        );
    }
}
