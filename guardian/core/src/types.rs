// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Client-enclave transport and plaintext witness types.

use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::pedersen::Blinding;
use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Matches `guardian::guardian::MAX_GUARDIAN_ENCLAVE_KEYS`.
pub const MAX_ENCLAVE_KEYS: usize = 16;

/// Matches the four limbs in `contra::encrypted_amount::EncryptedAmount`.
pub const U16_LIMBS: usize = 4;

/// A 32-byte payload key plus its 16-byte HPKE authentication tag.
pub(crate) const WRAPPED_PAYLOAD_KEY_LENGTH: usize = 32 + 16;

/// Cryptographic public-key types used by the enclave.
pub type SigningPublicKey = Ed25519PublicKey;
pub type EncryptionPublicKey = <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PublicKey;

/// Serialized enclave encryption public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct EncryptionPublicKeyBytes([u8; 32]);

impl From<&EncryptionPublicKey> for EncryptionPublicKeyBytes {
    fn from(pk: &EncryptionPublicKey) -> Self {
        use hpke::Serializable;

        Self(pk.to_bytes().into())
    }
}

/// The enclave's public keys.
#[derive(Serialize, Deserialize)]
pub struct EnclaveKeys {
    /// Ed25519 public key registered on chain for response verification.
    pub signing_pk: SigningPublicKey,
    /// X25519 public key used by clients to seal requests to this enclave.
    #[serde(with = "encryption_public_key_serde")]
    pub enc_pk: EncryptionPublicKey,
}

mod encryption_public_key_serde {
    use super::{EncryptionPublicKey, EncryptionPublicKeyBytes};
    use hpke::Deserializable;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        pk: &EncryptionPublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        EncryptionPublicKeyBytes::from(pk).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EncryptionPublicKey, D::Error> {
        let EncryptionPublicKeyBytes(bytes) = Deserialize::deserialize(deserializer)?;
        EncryptionPublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// One shared encrypted payload and one wrapped payload key per live on-chain enclave key.
// TODO: Replace the per-recipient HPKE encryption with a construction that directly encapsulates
// the shared payload key.
#[derive(Serialize, Deserialize)]
pub struct SealedRequest {
    pub(crate) version: u8,
    pub(crate) payload_nonce: [u8; 12],
    pub(crate) encrypted_payload: Vec<u8>,
    pub(crate) wrapped_keys: BTreeMap<EncryptionPublicKeyBytes, WrappedPayloadKey>,
}

/// One payload key sealed to a single enclave's HPKE public key.
#[derive(Serialize, Deserialize)]
pub(crate) struct WrappedPayloadKey {
    pub(crate) encapped_key: [u8; 32],
    #[serde(with = "serde_big_array::BigArray")]
    pub(crate) encrypted_key: [u8; WRAPPED_PAYLOAD_KEY_LENGTH],
}

/// An unsealed on-chain operation and the private witnesses needed to validate it.
#[derive(Serialize, Deserialize)]
pub enum UnsealedRequest {
    TransferRequest {
        old_encrypted_balance: EncryptedAmount,
        new_encrypted_balance: EncryptedAmount,
        recipients: Vec<TransferRecipient>,
        /// Sender secret key used only to verify the balance openings and derive `sender_pk`.
        x_a: PrivateKey,
        /// Plaintext value of `old_encrypted_balance`.
        old_balance: u64,
    },
    UnwrapRequest {
        old_encrypted_balance: EncryptedAmount,
        new_encrypted_balance: EncryptedAmount,
        amount: u64,
        /// Sender secret key used only to verify the balance openings and derive `sender_pk`.
        x_a: PrivateKey,
        /// Plaintext value of `old_encrypted_balance`.
        old_balance: u64,
    },
}

/// Encrypted limbs used for enclave verification and serialized with Move's exact
/// `contra::encrypted_amount::EncryptedAmount` BCS layout.
#[derive(Clone, Debug)]
pub struct EncryptedAmount {
    /// Encrypted limbs ordered from least to most significant.
    pub limbs: [Ciphertext; U16_LIMBS],
}

impl Serialize for EncryptedAmount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::move_types::serialize_encrypted_amount(self, serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedAmount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::move_types::deserialize_encrypted_amount(deserializer)
    }
}

/// One transfer recipient, including its on-chain fields and enclave-only plaintext witnesses.
#[derive(Serialize, Deserialize)]
pub struct TransferRecipient {
    /// Recipient key included in the on-chain transfer.
    pub receiver_pk: PublicKey,
    /// Exact encrypted amount included in the on-chain transfer.
    pub encrypted_amount: EncryptedAmount,
    /// Claimed little-endian plaintext limbs checked against `encrypted_amount`.
    pub amount: [u16; U16_LIMBS],
    /// Blinding of the collapsed `encrypted_amount`.
    pub blinding: Blinding,
}

/// The enclave's signature over a `GuardianRequest`, together with its signing public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnclaveResponse {
    /// Public key identifying the enclave that produced `signature`.
    pub signing_pk: SigningPublicKey,
    /// Ed25519 signature over the BCS `GuardianRequest`.
    pub signature: Ed25519Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::traits::ToFromBytes;
    use hpke::Deserializable;

    impl From<[u8; 32]> for EncryptionPublicKeyBytes {
        fn from(bytes: [u8; 32]) -> Self {
            Self(bytes)
        }
    }

    /// Must match Move's `guardian_tests::parse_user_data_round_trips`.
    #[test]
    fn enclave_keys_match_move_user_data() {
        let signing_pk =
            Hex::decode("aef3f4a4b8eca1dfc343361bf8e436bd42de9259c04b8314eb8e2054dd6e82ab")
                .unwrap();
        let keys = EnclaveKeys {
            signing_pk: SigningPublicKey::from_bytes(&signing_pk).unwrap(),
            enc_pk: EncryptionPublicKey::from_bytes(&[0xaa; 32]).unwrap(),
        };
        let bytes = bcs::to_bytes(&keys).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[..32], signing_pk);
        assert_eq!(&bytes[32..], [0xaa; 32]);
    }
}
