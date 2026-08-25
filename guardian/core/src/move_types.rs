// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! BCS mirrors of the Move types used in Guardian requests.

use crate::types::{EncryptedAmount, U16_LIMBS};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::pedersen::PedersenCommitment;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::twisted_elgamal::Ciphertext;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Exact BCS mirror of Move's `guardian::guardian::GuardianRequest`.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct GuardianRequest {
    /// Signed protocol version.
    version: u16,
    /// Blake2b-256 digest of the BCS operation binding.
    digest: Vec<u8>,
}

impl GuardianRequest {
    /// Signed-request protocol version. Increment before changing request or binding semantics.
    pub(crate) const VERSION: u16 = 1;

    /// Construct the exact message signed by the enclave and verified on chain.
    pub(crate) fn new(binding: &Binding) -> Self {
        Self {
            version: Self::VERSION,
            digest: binding.digest(),
        }
    }
}

/// Exact BCS mirror of `sui::group_ops::Element<T>`, which encodes as a length-prefixed
/// `vector<u8>` rather than `RistrettoPoint`'s bare 32 bytes.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MoveElement(Vec<u8>);

impl From<&RistrettoPoint> for MoveElement {
    fn from(point: &RistrettoPoint) -> Self {
        Self(point.to_byte_array().to_vec())
    }
}

impl MoveElement {
    fn into_point<E: serde::de::Error>(self) -> Result<RistrettoPoint, E> {
        let bytes = self
            .0
            .try_into()
            .map_err(|_| E::custom("Ristretto point must be 32 bytes"))?;
        RistrettoPoint::from_byte_array(&bytes).map_err(|_| E::custom("invalid Ristretto point"))
    }
}

/// Exact BCS mirror of `contra::twisted_elgamal::Encryption`.
#[derive(Debug, Serialize, Deserialize)]
struct MoveEncryption {
    ciphertext: MoveElement,
    decryption_handle: MoveElement,
}

impl From<&Ciphertext> for MoveEncryption {
    fn from(ciphertext: &Ciphertext) -> Self {
        Self {
            ciphertext: (&ciphertext.commitment().0).into(),
            decryption_handle: ciphertext.decryption_handle().into(),
        }
    }
}

impl MoveEncryption {
    fn into_ciphertext<E: serde::de::Error>(self) -> Result<Ciphertext, E> {
        Ok(Ciphertext::new(
            PedersenCommitment(self.ciphertext.into_point()?),
            self.decryption_handle.into_point()?,
        ))
    }
}

pub(crate) fn serialize_encrypted_amount<S: Serializer>(
    amount: &EncryptedAmount,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    amount
        .limbs
        .each_ref()
        .map(MoveEncryption::from)
        .serialize(serializer)
}

pub(crate) fn deserialize_encrypted_amount<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<EncryptedAmount, D::Error> {
    let [l0, l1, l2, l3] = <[MoveEncryption; U16_LIMBS]>::deserialize(deserializer)?;
    Ok(EncryptedAmount {
        limbs: [
            l0.into_ciphertext()?,
            l1.into_ciphertext()?,
            l2.into_ciphertext()?,
            l3.into_ciphertext()?,
        ],
    })
}

/// Exact BCS mirror of `contra::authority::Binding`. Changing its layout or meaning requires
/// incrementing the request version and updating the cross-language fixtures.
#[derive(Debug, Serialize)]
pub(crate) enum Binding {
    Transfer {
        sender_pk: MoveElement,
        receiver_pks: Vec<MoveElement>,
        old_encrypted_balance: EncryptedAmount,
        new_encrypted_balance: EncryptedAmount,
        encrypted_amounts: Vec<EncryptedAmount>,
    },
    Unwrap {
        sender_pk: MoveElement,
        old_encrypted_balance: EncryptedAmount,
        new_encrypted_balance: EncryptedAmount,
        amount: u64,
    },
}

impl Binding {
    /// Matches `contra::authority::digest`: Blake2b-256 of the BCS-encoded binding.
    fn digest(&self) -> Vec<u8> {
        Blake2b256::digest(bcs::to_bytes(self).expect("binding is BCS-serializable")).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::ristretto255::RistrettoScalar;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::pedersen::PedersenCommitment;

    fn zero_amount() -> EncryptedAmount {
        let zero = || {
            Ciphertext::new(
                PedersenCommitment(RistrettoPoint::zero()),
                RistrettoPoint::zero(),
            )
        };
        EncryptedAmount {
            limbs: [zero(), zero(), zero(), zero()],
        }
    }

    fn element(point: RistrettoPoint) -> MoveElement {
        (&point).into()
    }

    fn tagged_encryption(ciphertext: u64, handle: u64) -> Ciphertext {
        Ciphertext::new(
            PedersenCommitment(RistrettoPoint::generator() * RistrettoScalar::from(ciphertext)),
            RistrettoPoint::generator() * RistrettoScalar::from(handle),
        )
    }

    fn tagged_amount(offset: u64) -> EncryptedAmount {
        EncryptedAmount {
            limbs: [
                tagged_encryption(offset + 1, offset + 2),
                tagged_encryption(offset + 3, offset + 4),
                tagged_encryption(offset + 5, offset + 6),
                tagged_encryption(offset + 7, offset + 8),
            ],
        }
    }

    fn zero_transfer_binding() -> Binding {
        Binding::Transfer {
            sender_pk: element(RistrettoPoint::generator()),
            receiver_pks: vec![element(RistrettoPoint::generator())],
            old_encrypted_balance: zero_amount(),
            new_encrypted_balance: zero_amount(),
            encrypted_amounts: vec![zero_amount()],
        }
    }

    /// Must match `guardian_tests::transfer_binding_digest_regression`.
    #[test]
    fn transfer_binding_matches_move() {
        assert_eq!(
            Hex::encode(zero_transfer_binding().digest()),
            "23c5d517304afc26e1651eae6ed659d8109f14db6565420135ce9ce1ada495a3"
        );
    }

    /// Must match `guardian_tests::distinct_limb_binding_digest_regression`.
    #[test]
    fn distinct_limb_binding_regression() {
        let binding = Binding::Transfer {
            sender_pk: element(RistrettoPoint::generator()),
            receiver_pks: vec![element(RistrettoPoint::generator())],
            old_encrypted_balance: tagged_amount(10),
            new_encrypted_balance: tagged_amount(20),
            encrypted_amounts: vec![tagged_amount(30)],
        };
        assert_eq!(
            Hex::encode(binding.digest()),
            "92b3b166c324b7e048a4002d702051b7220bdc7a4f05b500f45dcfe92ce33e2e"
        );
    }

    /// Must match `guardian_tests::unwrap_binding_digest_regression`.
    #[test]
    fn unwrap_binding_matches_move() {
        let binding = Binding::Unwrap {
            sender_pk: element(RistrettoPoint::generator()),
            old_encrypted_balance: zero_amount(),
            new_encrypted_balance: zero_amount(),
            amount: 42,
        };
        assert_eq!(
            Hex::encode(binding.digest()),
            "c7955a80ffafd87ccd7f806ec2e20b80b2a14669cd8d63813d682bcff2856070"
        );
    }

    /// Must match `guardian_tests::guardian_request_serde`.
    #[test]
    fn guardian_request_matches_move() {
        assert_eq!(
            Hex::encode(bcs::to_bytes(&GuardianRequest::new(&zero_transfer_binding())).unwrap()),
            "01002023c5d517304afc26e1651eae6ed659d8109f14db6565420135ce9ce1ada495a3"
        );
    }
}
