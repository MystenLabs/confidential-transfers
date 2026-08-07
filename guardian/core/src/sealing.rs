// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HPKE (X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305) sealing of the request to
//! all enclave instances' key in the fleet.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::types::UnsealedRequest;
use crate::GuardianError;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
#[cfg(any(test, feature = "testing"))]
use hpke::OpModeS;
#[cfg(any(test, feature = "testing"))]
use hpke::Serializable;
use hpke::{Deserializable, Kem, OpModeR};

const INFO: &[u8] = b"contra-guardian-v1";

type PrivateKey = <X25519HkdfSha256 as Kem>::PrivateKey;
type EncappedKey = <X25519HkdfSha256 as Kem>::EncappedKey;

/// The sealed request wire-format version.
pub const SEALED_REQUEST_VERSION: u8 = 1;

/// The `/process_request` body: the request sealed to every live enclave key, one envelope each,
/// BCS-encoded.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedRequest {
    pub version: u8,
    pub sealed: Vec<SealedEnvelope>,
}

/// One HPKE seal of the request to a single enclave key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    encapped_key: [u8; 32],
    ciphertext: Vec<u8>,
}

/// Seal a request to every live `enc_pk`, one envelope each — the client half, mirrored
/// by the SDK and used by tests.
#[cfg(any(test, feature = "testing"))]
pub fn seal_to_all(enc_pks: &[[u8; 32]], req: &UnsealedRequest) -> Result<SealedRequest> {
    if enc_pks.is_empty() {
        return Err(anyhow!("no enclave keys to seal to"));
    }
    let plaintext = bcs::to_bytes(req)?;
    Ok(SealedRequest {
        version: SEALED_REQUEST_VERSION,
        sealed: enc_pks
            .iter()
            .map(|pk| seal(pk, &plaintext))
            .collect::<Result<_>>()?,
    })
}

#[cfg(any(test, feature = "testing"))]
fn seal(enc_pk: &[u8; 32], plaintext: &[u8]) -> Result<SealedEnvelope> {
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(enc_pk)
        .map_err(|e| anyhow!("bad enc_pk: {e}"))?;
    let mut rng = rand::thread_rng();
    let (encapped, ciphertext) = hpke::single_shot_seal::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &pk, INFO, plaintext, &[], &mut rng)
    .map_err(|e| anyhow!("seal failed: {e}"))?;
    Ok(SealedEnvelope {
        encapped_key: encapped.to_bytes().into(),
        ciphertext,
    })
}

/// Open one envelope and decode the request, failing with [GuardianError::NotARecipient]
/// when it is not addressed to `sk`.
pub(crate) fn open(sk: &PrivateKey, sealed: &SealedEnvelope) -> crate::Result<UnsealedRequest> {
    let encapped =
        EncappedKey::from_bytes(&sealed.encapped_key).map_err(|_| GuardianError::NotARecipient)?;
    let plaintext = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        sk,
        &encapped,
        INFO,
        &sealed.ciphertext,
        &[],
    )
    .map_err(|_| GuardianError::NotARecipient)?;
    bcs::from_bytes(&plaintext).map_err(|_| GuardianError::MalformedRequest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::transfer_request as request;
    use crate::{EnclaveKeyPair, GuardianError};

    #[test]
    fn seals_to_many_and_unseals_own_envelope() {
        let keypair = EnclaveKeyPair::from_seed_for_testing();
        let siblings = [EnclaveKeyPair::generate(), EnclaveKeyPair::generate()];
        let (mine, a, b) = (
            keypair.keys().enc_pk,
            siblings[0].keys().enc_pk,
            siblings[1].keys().enc_pk,
        );
        for fleet in [[mine, a, b], [a, mine, b], [a, b, mine]] {
            let sealed = seal_to_all(&fleet, &request()).unwrap();
            assert_eq!(sealed.version, SEALED_REQUEST_VERSION);
            let opened = keypair.unseal(&sealed.sealed).unwrap();
            assert_eq!(
                bcs::to_bytes(&opened).unwrap(),
                bcs::to_bytes(&request()).unwrap()
            );
        }
    }

    #[test]
    fn rejects_envelopes_for_other_instances() {
        let keypair = EnclaveKeyPair::from_seed_for_testing();
        let sibling = EnclaveKeyPair::generate();
        let sealed = seal_to_all(&[sibling.keys().enc_pk], &request()).unwrap();
        assert_eq!(
            keypair.unseal(&sealed.sealed).unwrap_err(),
            GuardianError::NotARecipient
        );
    }

    #[test]
    fn rejects_malformed_plaintext() {
        let keypair = EnclaveKeyPair::from_seed_for_testing();
        let envelope = seal(&keypair.keys().enc_pk, b"not a bcs request").unwrap();
        assert_eq!(
            keypair.unseal(&[envelope]).unwrap_err(),
            GuardianError::MalformedRequest
        );
    }

    #[test]
    fn rejects_empty_key_set() {
        assert!(seal_to_all(&[], &request()).is_err());
    }
}
