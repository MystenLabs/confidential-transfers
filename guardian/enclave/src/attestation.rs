// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Attestation from the Nitro Secure Module.

use contra_guardian_core::types::EnclaveKeys;

/// Return a Nitro attestation document committing to the enclave's public keys in `user_data`.
#[cfg(all(target_os = "linux", not(test)))]
pub(crate) fn attestation_document(keys: &EnclaveKeys) -> anyhow::Result<Vec<u8>> {
    use nsm_api::api::{Request, Response};
    use nsm_api::driver;
    use serde_bytes::ByteBuf;

    let user_data = bcs::to_bytes(keys)?;
    let fd = driver::nsm_init();
    anyhow::ensure!(fd >= 0, "failed to open the Nitro Secure Module");
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

#[cfg(any(not(target_os = "linux"), test))]
pub(crate) fn attestation_document(_keys: &EnclaveKeys) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!("Nitro attestation requires a Linux enclave with NSM")
}
