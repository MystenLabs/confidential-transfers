// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Attestation from the Nitro Secure Module, or under `non-enclave-dev` the `user_data`
//! alone so the guardian runs outside an enclave.

use contra_guardian_core::types::EnclaveKeys;

/// An attestation document committing to the enclave's keys in `user_data`, laid out as
/// `guardian::parse_user_data` expects.
#[cfg(not(feature = "non-enclave-dev"))]
pub(crate) fn attestation_document(keys: &EnclaveKeys) -> anyhow::Result<Vec<u8>> {
    use nsm_api::api::{Request, Response};
    use nsm_api::driver;
    use serde_bytes::ByteBuf;

    let user_data = bcs::to_bytes(keys)?;
    let fd = driver::nsm_init();
    let response = driver::nsm_process_request(
        fd,
        Request::Attestation {
            user_data: Some(ByteBuf::from(user_data)),
            nonce: None,
            public_key: None,
        },
    );
    driver::nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        other => anyhow::bail!("unexpected NSM response: {other:?}"),
    }
}

/// Serves a mocked/invalid attestation containing keys in dev mode.
#[cfg(feature = "non-enclave-dev")]
pub(crate) fn attestation_document(keys: &EnclaveKeys) -> anyhow::Result<Vec<u8>> {
    // Announce the stub once so a dev binary is never mistaken for a real enclave.
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!("no Nitro attestation (non-enclave-dev build) — not a real enclave");
    });
    Ok(bcs::to_bytes(keys)?)
}
