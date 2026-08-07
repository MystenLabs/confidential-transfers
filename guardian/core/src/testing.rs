// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deterministic fixtures shared by the unit tests, the e2e suite, and the dev CLI.

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};

use crate::types::{Recipient, RequestPayload, UnsealedRequest};

/// A well-formed encryption of `m` to `pk` with a chosen blinding `r`, built directly
/// because `Ciphertext::encrypt` picks its own randomness and caps the message at `u32`.
pub fn encrypt(m: u64, pk: &PublicKey, r: u64) -> Ciphertext {
    let r = Blinding(RistrettoScalar::from(r));
    Ciphertext::new(
        PedersenCommitment::new(&RistrettoScalar::from(m), &r),
        *pk.as_point() * r.0,
    )
}

/// Sender (sk 12345) holds 100, sends 40 to one recipient (sk 67890), keeps 60.
pub fn transfer_request() -> UnsealedRequest {
    let x_a = PrivateKey::new(RistrettoScalar::from(12345u64));
    let pk_a = PublicKey::from(&x_a);
    let pk_b = PublicKey::from(&PrivateKey::new(RistrettoScalar::from(67890u64)));
    UnsealedRequest::TransferRequest {
        old_encrypted_balance: encrypt(100, &pk_a, 1),
        new_encrypted_balance: encrypt(60, &pk_a, 2),
        recipients: vec![Recipient {
            encrypted_amount: encrypt(40, &pk_b, 3),
            receiver_pk: pk_b,
            amount: 40,
            blinding: Blinding(RistrettoScalar::from(3u64)),
        }],
        x_a,
        old_balance: 100,
    }
}

/// The signed payload, reconstructed for verifying a response the way the wallet does.
pub fn transfer_payload(req: &UnsealedRequest) -> RequestPayload {
    let UnsealedRequest::TransferRequest {
        old_encrypted_balance,
        new_encrypted_balance,
        recipients,
        x_a,
        ..
    } = req
    else {
        panic!("fixture is a transfer")
    };
    RequestPayload::Transfer {
        sender_pk: PublicKey::from(x_a).as_point().into(),
        receiver_pks: recipients
            .iter()
            .map(|r| r.receiver_pk.as_point().into())
            .collect(),
        old_encrypted_balance: old_encrypted_balance.into(),
        new_encrypted_balance: new_encrypted_balance.into(),
        encrypted_amounts: recipients
            .iter()
            .map(|r| (&r.encrypted_amount).into())
            .collect(),
    }
}
