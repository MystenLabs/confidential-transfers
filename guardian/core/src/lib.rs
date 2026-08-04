// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian second factor: re-checks confidential transfer arithmetic in plaintext and
//! signs a response the chain verifies against a registered enclave key (design:
//! `guardian/README.md`).

pub(crate) mod checks;
pub mod types;

use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, Signer};
use thiserror::Error;

use crate::types::{EnclaveKeys, EnclaveRequest, EnclaveResponse, EncryptionPublicKey};

pub type Result<T> = std::result::Result<T, GuardianError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuardianError {
    #[error("transfer has no recipients")]
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

/// An enclave's keys, where `signing_key` never leaves the enclave and `enc_pk` is the
/// X25519 key clients seal requests to.
pub struct Guardian {
    keypair: Ed25519KeyPair,
    enc_pk: EncryptionPublicKey,
}

impl Guardian {
    pub fn new(keypair: Ed25519KeyPair, enc_pk: EncryptionPublicKey) -> Self {
        Self { keypair, enc_pk }
    }

    /// The keys to embed in the attestation's `user_data`, laid out as
    /// `guardian::parse_user_data` expects.
    pub fn keys(&self) -> EnclaveKeys {
        EnclaveKeys {
            signing_pk: self.keypair.public().clone(),
            enc_pk: self.enc_pk.clone(),
        }
    }

    /// Validate the request and sign the payload the chain will rebuild, answering a bad
    /// request with the reason it was refused.
    pub fn approve(&self, req: &EnclaveRequest) -> EnclaveResponse {
        match checks::construct_payload(req) {
            Ok(payload) => EnclaveResponse::Success {
                signing_pk: self.keypair.public().clone(),
                signature: Box::new(self.keypair.sign(&payload.to_bytes())),
            },
            Err(e) => EnclaveResponse::Error {
                error: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::{EnclaveRequest, Recipient};
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use fastcrypto::groups::GroupElement;
    use fastcrypto::pedersen::{Blinding, PedersenCommitment, H};
    use fastcrypto::serde_helpers::BytesRepresentation;
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
        let guardian = Guardian::new(
            Ed25519KeyPair::from_bytes(&seed).unwrap(),
            BytesRepresentation([0xaa; 32]),
        );

        let req = EnclaveRequest::TransferRequest {
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

        let EnclaveResponse::Success {
            signing_pk,
            signature,
        } = guardian.approve(&req)
        else {
            panic!("valid request must be approved")
        };
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
        let guardian = Guardian::new(
            Ed25519KeyPair::from_bytes(&seed).unwrap(),
            BytesRepresentation([0xaa; 32]),
        );
        let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
        let pk_a = PublicKey::from(&x_a);
        // Claims 200 while the balance ciphertext encrypts 100.
        let req = EnclaveRequest::UnwrapRequest {
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
        let _ = pk_a;
        let EnclaveResponse::Error { error } = guardian.approve(&req) else {
            panic!("bad request must be refused")
        };
        assert_eq!(error, "old balance does not open to the claimed value");
    }
}
