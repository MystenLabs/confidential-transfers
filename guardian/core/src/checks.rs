// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Plaintext witness validation and construction of the exact operation binding signed on chain.

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};

use crate::move_types::{Binding, GuardianRequest};
use crate::types::{EncryptedAmount, UnsealedRequest};
use crate::{GuardianError, Result};

/// Matches Contra's on-chain `MAX_BATCH_RECIPIENTS`.
const MAX_BATCH_RECIPIENTS: usize = 255;

/// An operation binding that can only be constructed after all plaintext checks pass.
#[derive(Debug)]
struct VerifiedBinding(Binding);

/// Validate `req` and return the BCS `GuardianRequest` bytes for signing.
pub(super) fn verified_request_bytes(req: &UnsealedRequest) -> Result<Vec<u8>> {
    let VerifiedBinding(binding) = verify_binding(req)?;
    Ok(bcs::to_bytes(&GuardianRequest::new(&binding)).expect("request is BCS-serializable"))
}

/// Validate the plaintext operation against its encrypted amounts, then construct the exact
/// operation binding that Contra will execute.
fn verify_binding(req: &UnsealedRequest) -> Result<VerifiedBinding> {
    let binding = match req {
        UnsealedRequest::TransferRequest {
            old_encrypted_balance,
            new_encrypted_balance,
            recipients,
            x_a,
            old_balance,
        } => {
            if recipients.is_empty() {
                return Err(GuardianError::EmptyTransfer);
            }
            if recipients.len() > MAX_BATCH_RECIPIENTS {
                return Err(GuardianError::TooManyRecipients(recipients.len()));
            }

            let total_txn_amount = recipients
                .iter()
                .try_fold(0u64, |total, recipient| total.checked_add(recipient.amount))
                .ok_or(GuardianError::TransferAmountOverflow)?;
            let new_balance = old_balance
                .checked_sub(total_txn_amount)
                .ok_or(GuardianError::Overdraft)?;
            verify_balance_opening(old_encrypted_balance, x_a, *old_balance)?;

            let mut receiver_pks = Vec::with_capacity(recipients.len());
            let mut encrypted_amounts = Vec::with_capacity(recipients.len());
            for (i, recipient) in recipients.iter().enumerate() {
                collapse(&recipient.encrypted_amount)
                    .verify(
                        &RistrettoScalar::from(recipient.amount),
                        &recipient.receiver_pk,
                        &recipient.blinding,
                    )
                    .map_err(|_| GuardianError::RecipientAmountMismatch { recipient: i })?;
                receiver_pks.push(recipient.receiver_pk.as_point().into());
                encrypted_amounts.push(recipient.encrypted_amount.clone());
            }

            verify_balance_opening(new_encrypted_balance, x_a, new_balance)?;

            Binding::Transfer {
                sender_pk: PublicKey::from(x_a).as_point().into(),
                receiver_pks,
                old_encrypted_balance: old_encrypted_balance.clone(),
                new_encrypted_balance: new_encrypted_balance.clone(),
                encrypted_amounts,
            }
        }
        UnsealedRequest::UnwrapRequest {
            old_encrypted_balance,
            new_encrypted_balance,
            amount,
            x_a,
            old_balance,
        } => {
            let new_balance = old_balance
                .checked_sub(*amount)
                .ok_or(GuardianError::Overdraft)?;
            verify_balance_opening(old_encrypted_balance, x_a, *old_balance)?;
            verify_balance_opening(new_encrypted_balance, x_a, new_balance)?;

            Binding::Unwrap {
                sender_pk: PublicKey::from(x_a).as_point().into(),
                old_encrypted_balance: old_encrypted_balance.clone(),
                new_encrypted_balance: new_encrypted_balance.clone(),
                amount: *amount,
            }
        }
    };
    Ok(VerifiedBinding(binding))
}

/// Verify that the collapsed encrypted balance opens to `plaintext` under `x_a`.
fn verify_balance_opening(
    encrypted_balance: &EncryptedAmount,
    x_a: &PrivateKey,
    plaintext: u64,
) -> Result<()> {
    collapse(encrypted_balance)
        .verify_opening(&RistrettoScalar::from(plaintext), x_a)
        .map_err(|_| GuardianError::BalanceMismatch)
}

/// Collapse four base-2^16 ciphertext limbs into one ciphertext.
fn collapse(encrypted_amount: &EncryptedAmount) -> Ciphertext {
    let shift = RistrettoScalar::from(1u64 << 16);
    encrypted_amount.limbs[..3]
        .iter()
        .rev()
        .fold(encrypted_amount.limbs[3].clone(), |amount, limb| {
            amount * shift + limb.clone()
        })
}

#[cfg(test)]
#[path = "test/checks.rs"]
mod tests;
