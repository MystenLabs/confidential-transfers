// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Wire types matching `contra::guardian`.

use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::pedersen::Blinding;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};

/// Mirrors `sui::group_ops::Element<T>`, which BCS-encodes as a length-prefixed `Vec<u8>`
/// rather than `RistrettoPoint`'s bare 32 bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveElement(Vec<u8>);

impl From<&RistrettoPoint> for MoveElement {
    fn from(point: &RistrettoPoint) -> Self {
        Self(point.to_byte_array().to_vec())
    }
}

/// Mirrors `contra::twisted_elgamal::Encryption`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveCiphertext {
    commitment: MoveElement,
    decryption_handle: MoveElement,
}

impl From<&Ciphertext> for MoveCiphertext {
    fn from(ciphertext: &Ciphertext) -> Self {
        Self {
            commitment: (&ciphertext.commitment().0).into(),
            decryption_handle: ciphertext.decryption_handle().into(),
        }
    }
}

/// The payload the enclave signs, either a transfer or an unwrap transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RequestPayload {
    Transfer {
        sender_pk: MoveElement,
        receiver_pks: Vec<MoveElement>,
        old_encrypted_balance: MoveCiphertext,
        new_encrypted_balance: MoveCiphertext,
        encrypted_amounts: Vec<MoveCiphertext>,
    },
    Unwrap {
        sender_pk: MoveElement,
        old_encrypted_balance: MoveCiphertext,
        new_encrypted_balance: MoveCiphertext,
        amount: u64,
    },
}

/// The enclave's public keys as BCS-encoded into the attestation's `user_data`, 32 bytes of
/// `signing_pk` then 32 of `enc_pk`.
#[derive(Serialize, Deserialize)]
pub struct EnclaveKeys {
    pub signing_pk: Ed25519PublicKey,
    pub enc_pk: [u8; 32],
}

/// What a client asks the guardian to approve, where `x_a` opens both balances and
/// `old_balance` is supplied so the enclave never solves a discrete log.
#[derive(Debug, Serialize, Deserialize)]
pub enum UnsealedRequest {
    TransferRequest {
        old_encrypted_balance: Ciphertext,
        new_encrypted_balance: Ciphertext,
        recipients: Vec<Recipient>,
        // Private witnesses.
        x_a: PrivateKey,
        old_balance: u64,
    },
    UnwrapRequest {
        old_encrypted_balance: Ciphertext,
        new_encrypted_balance: Ciphertext,
        amount: u64,
        // Private witnesses.
        x_a: PrivateKey,
        old_balance: u64,
    },
}

/// One recipient of a transfer, grouped per recipient so the per-recipient fields cannot
/// disagree in length.
#[derive(Debug, Serialize, Deserialize)]
pub struct Recipient {
    pub receiver_pk: PublicKey,
    pub encrypted_amount: Ciphertext,
    // Private witnesses.
    pub amount: u64,
    pub blinding: Blinding,
}

/// The enclave's signature over the payload, together with the key that produced it.
#[derive(Debug, Serialize)]
pub struct EnclaveResponse {
    pub signing_pk: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::GroupElement;
    use fastcrypto::pedersen::PedersenCommitment;
    use fastcrypto::traits::ToFromBytes;

    fn zero_ciphertext() -> MoveCiphertext {
        (&Ciphertext::new(
            PedersenCommitment(RistrettoPoint::zero()),
            RistrettoPoint::zero(),
        ))
            .into()
    }

    fn element(p: RistrettoPoint) -> MoveElement {
        (&p).into()
    }

    /// Must match `guardian_tests::request_payload_serde`.
    #[test]
    fn transfer_payload_matches_move() {
        let payload = RequestPayload::Transfer {
            sender_pk: element(RistrettoPoint::generator()),
            receiver_pks: vec![element(RistrettoPoint::zero())],
            old_encrypted_balance: zero_ciphertext(),
            new_encrypted_balance: zero_ciphertext(),
            encrypted_amounts: vec![zero_ciphertext()],
        };
        assert_eq!(
            Hex::encode(bcs::to_bytes(&payload).unwrap()),
            "0020e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d760120000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    /// Must match `guardian_tests::unwrap_request_payload_serde`.
    #[test]
    fn unwrap_payload_matches_move() {
        let payload = RequestPayload::Unwrap {
            sender_pk: element(RistrettoPoint::generator()),
            old_encrypted_balance: zero_ciphertext(),
            new_encrypted_balance: zero_ciphertext(),
            amount: 42,
        };
        assert_eq!(
            Hex::encode(bcs::to_bytes(&payload).unwrap()),
            "0120e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d762000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002a00000000000000"
        );
    }

    /// The attestation's `user_data`: the bytes `guardian::parse_user_data` slices.
    #[test]
    fn enclave_keys_match_move_user_data() {
        let keys = EnclaveKeys {
            signing_pk: Ed25519PublicKey::from_bytes(&[0xaa; 32]).unwrap(),
            enc_pk: [0xbb; 32],
        };
        let bytes = bcs::to_bytes(&keys).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[..32], [0xaa; 32]);
        assert_eq!(&bytes[32..], [0xbb; 32]);
    }
}
