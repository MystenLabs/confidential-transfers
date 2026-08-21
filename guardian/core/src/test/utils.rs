// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deterministic fixtures shared by this crate's unit-test modules.

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};

use crate::types::{EncryptedAmount, Recipient, UnsealedRequest, U16_LIMBS};

/// Fixed per-limb encryption randomness for tests.
pub(crate) const TEST_BLINDINGS: [u64; U16_LIMBS] = [1, 2, 3, 4];

/// Encrypt the canonical little-endian u16 limbs of `value` with the supplied blindings.
pub(crate) fn encrypt_amount(
    value: u64,
    pk: &PublicKey,
    blindings: [u64; U16_LIMBS],
) -> EncryptedAmount {
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
pub(crate) fn blinding(values: [u64; U16_LIMBS]) -> Blinding {
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
pub(crate) fn transfer_request() -> UnsealedRequest {
    let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
    let pk_a = PublicKey::from(&x_a);
    let pk_b = PublicKey::from(&PrivateKey::new(RistrettoScalar::from(67890u64)));
    UnsealedRequest::TransferRequest {
        old_encrypted_balance: encrypt_amount(100, &pk_a, TEST_BLINDINGS),
        new_encrypted_balance: encrypt_amount(60, &pk_a, TEST_BLINDINGS),
        recipients: vec![Recipient {
            encrypted_amount: encrypt_amount(40, &pk_b, TEST_BLINDINGS),
            receiver_pk: pk_b,
            amount: 40,
            blinding: blinding(TEST_BLINDINGS),
        }],
        x_a,
        old_balance: 100,
    }
}
