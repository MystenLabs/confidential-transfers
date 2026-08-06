// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The plaintext arithmetic the guardian re-checks.

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::twisted_elgamal::{Ciphertext, PrivateKey, PublicKey};

use crate::types::{RequestPayload, UnsealedRequest};
use crate::{GuardianError, Result};

/// Envelope for [UnsealedRequest] after validation.
#[derive(Debug)]
pub struct VerifiedRequestPayload(RequestPayload);

impl VerifiedRequestPayload {
    /// The BCS bytes the enclave signs and the chain rebuilds.
    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self.0).expect("payload is BCS-serializable")
    }
}

/// Validate a request and construct the payload.
pub fn verify_payload(req: &UnsealedRequest) -> Result<VerifiedRequestPayload> {
    let payload = match req {
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

            let total_txn_amount = recipients
                .iter()
                .try_fold(0u64, |acc, r| acc.checked_add(r.amount))
                .ok_or(GuardianError::Overdraft)?;

            check_balances(
                old_encrypted_balance,
                new_encrypted_balance,
                x_a,
                *old_balance,
                total_txn_amount,
            )?;

            // Each ciphertext must encrypt its claimed amount to that recipient.
            for (i, r) in recipients.iter().enumerate() {
                r.encrypted_amount
                    .verify(
                        &RistrettoScalar::from(r.amount),
                        &r.receiver_pk,
                        &r.blinding,
                    )
                    .map_err(|_| GuardianError::AmountMismatch(i))?;
            }

            RequestPayload::Transfer {
                sender_pk: PublicKey::from(x_a).as_point().into(), // Derived from `x_a`
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
        UnsealedRequest::UnwrapRequest {
            old_encrypted_balance,
            new_encrypted_balance,
            amount,
            x_a,
            old_balance,
        } => {
            check_balances(
                old_encrypted_balance,
                new_encrypted_balance,
                x_a,
                *old_balance,
                *amount,
            )?;

            RequestPayload::Unwrap {
                sender_pk: PublicKey::from(x_a).as_point().into(),
                old_encrypted_balance: old_encrypted_balance.into(),
                new_encrypted_balance: new_encrypted_balance.into(),
                amount: *amount,
            }
        }
    };
    Ok(VerifiedRequestPayload(payload))
}

/// Check, for both transfers and unwraps, that the old and new balances open under `x_a`
/// and `new_balance = old_balance - total_txn_amount`.
fn check_balances(
    old_encrypted_balance: &Ciphertext,
    new_encrypted_balance: &Ciphertext,
    x_a: &PrivateKey,
    old_balance: u64,
    total_txn_amount: u64,
) -> Result<()> {
    let new_balance = old_balance
        .checked_sub(total_txn_amount)
        .ok_or(GuardianError::Overdraft)?;
    old_encrypted_balance
        .verify_opening(&RistrettoScalar::from(old_balance), x_a)
        .map_err(|_| GuardianError::OldBalanceMismatch)?;
    new_encrypted_balance
        .verify_opening(&RistrettoScalar::from(new_balance), x_a)
        .map_err(|_| GuardianError::NewBalanceMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Recipient;
    use fastcrypto::pedersen::{Blinding, PedersenCommitment};

    const SENDER: u64 = 12345;
    const RECIPIENT_1: u64 = 67890;
    const RECIPIENT_2: u64 = 11111;
    const ATTACKER: u64 = 999;

    fn sk(seed: u64) -> PrivateKey {
        PrivateKey::new(RistrettoScalar::from(seed))
    }

    fn pk(seed: u64) -> PublicKey {
        PublicKey::from(&sk(seed))
    }

    fn blinding(r: u64) -> Blinding {
        Blinding(RistrettoScalar::from(r))
    }

    /// A well-formed encryption of `m` to `pk` with a chosen blinding `r`.
    fn encrypt(m: u64, pk: &PublicKey, r: u64) -> Ciphertext {
        let r = blinding(r);
        Ciphertext::new(
            PedersenCommitment::new(&RistrettoScalar::from(m), &r),
            *pk.as_point() * r.0,
        )
    }

    /// A consistent recipient: the ciphertext encrypts the claimed amount to the receiver.
    fn recipient(receiver: u64, amount: u64, r: u64) -> Recipient {
        Recipient {
            receiver_pk: pk(receiver),
            encrypted_amount: encrypt(amount, &pk(receiver), r),
            amount,
            blinding: blinding(r),
        }
    }

    /// A transfer described in plaintext; `build` encrypts under the sender's key.
    struct Transfer {
        claimed_old_balance: u64,
        encrypted_old_balance: u64,
        encrypted_new_balance: u64,
        recipients: Vec<Recipient>,
    }

    impl Transfer {
        fn build(self) -> UnsealedRequest {
            let x_a = sk(SENDER);
            let pk_a = PublicKey::from(&x_a);
            UnsealedRequest::TransferRequest {
                old_encrypted_balance: encrypt(self.encrypted_old_balance, &pk_a, 1),
                new_encrypted_balance: encrypt(self.encrypted_new_balance, &pk_a, 2),
                recipients: self.recipients,
                x_a,
                old_balance: self.claimed_old_balance,
            }
        }
    }

    /// An unwrap described the same way.
    struct Unwrap {
        claimed_old_balance: u64,
        encrypted_old_balance: u64,
        encrypted_new_balance: u64,
        amount: u64,
    }

    impl Unwrap {
        fn build(self) -> UnsealedRequest {
            let x_a = sk(SENDER);
            let pk_a = PublicKey::from(&x_a);
            UnsealedRequest::UnwrapRequest {
                old_encrypted_balance: encrypt(self.encrypted_old_balance, &pk_a, 1),
                new_encrypted_balance: encrypt(self.encrypted_new_balance, &pk_a, 2),
                amount: self.amount,
                x_a,
                old_balance: self.claimed_old_balance,
            }
        }
    }

    /// Sender holds 100, transfers 30 and 20, keeps 50.
    #[test]
    fn accepts_valid_transfer() {
        let req = Transfer {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 50,
            recipients: vec![recipient(RECIPIENT_1, 30, 3), recipient(RECIPIENT_2, 20, 4)],
        };
        assert!(verify_payload(&req.build()).is_ok());
    }

    /// Sender holds 100, unwraps 40, keeps 60.
    #[test]
    fn accepts_valid_unwrap() {
        let req = Unwrap {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 60,
            amount: 40,
        };
        assert!(verify_payload(&req.build()).is_ok());
    }

    /// Unwrap the entire balance so new balance is 0 passes.
    #[test]
    fn accepts_full_balance_spend() {
        let req = Unwrap {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 0,
            amount: 100,
        };
        assert!(verify_payload(&req.build()).is_ok());
    }

    /// Claims 200 while the balance ciphertext encrypts 100.
    #[test]
    fn rejects_wrong_claimed_balance() {
        let req = Transfer {
            claimed_old_balance: 200,
            encrypted_old_balance: 100,
            encrypted_new_balance: 50,
            recipients: vec![recipient(RECIPIENT_1, 30, 3), recipient(RECIPIENT_2, 20, 4)],
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::OldBalanceMismatch
        );
    }

    /// The claimed balance of 10 opens correctly, but sends 30.
    #[test]
    fn rejects_overdraft() {
        let req = Transfer {
            claimed_old_balance: 10,
            encrypted_old_balance: 10,
            encrypted_new_balance: 0,
            recipients: vec![recipient(RECIPIENT_1, 30, 3)],
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::Overdraft
        );
    }

    /// The classic value-minting attempt: keep 80 where 100 - 50 leaves 50.
    #[test]
    fn rejects_inflated_new_balance() {
        let req = Transfer {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 80,
            recipients: vec![recipient(RECIPIENT_1, 30, 3), recipient(RECIPIENT_2, 20, 4)],
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::NewBalanceMismatch
        );
    }

    /// The second ciphertext encrypts 19 where the request claims 20.
    #[test]
    fn rejects_amount_not_matching_its_ciphertext() {
        let req = Transfer {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 50,
            recipients: vec![
                recipient(RECIPIENT_1, 30, 3),
                Recipient {
                    receiver_pk: pk(RECIPIENT_2),
                    encrypted_amount: encrypt(19, &pk(RECIPIENT_2), 4),
                    amount: 20,
                    blinding: blinding(4),
                },
            ],
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::AmountMismatch(1)
        );
    }

    /// The first ciphertext encrypts 30 to the attacker instead of to `RECIPIENT_1`.
    #[test]
    fn rejects_amount_keyed_to_the_wrong_recipient() {
        let req = Transfer {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 50,
            recipients: vec![
                Recipient {
                    receiver_pk: pk(RECIPIENT_1),
                    encrypted_amount: encrypt(30, &pk(ATTACKER), 3),
                    amount: 30,
                    blinding: blinding(3),
                },
                recipient(RECIPIENT_2, 20, 4),
            ],
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::AmountMismatch(0)
        );
    }

    /// A transfer with zero recipients.
    #[test]
    fn rejects_empty_transfer() {
        let req = Transfer {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 100,
            recipients: vec![],
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::EmptyTransfer
        );
    }

    /// Two amounts summing to 2^64 must be caught as an overdraft rather than wrapping
    /// to an apparently valid total of zero.
    #[test]
    fn rejects_wrapping_total() {
        let big = u64::MAX / 2 + 1;
        let req = Transfer {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 100,
            recipients: vec![
                recipient(RECIPIENT_1, big, 3),
                recipient(RECIPIENT_2, big, 4),
            ],
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::Overdraft
        );
    }

    /// Claims 200 while the balance ciphertext encrypts 100.
    #[test]
    fn rejects_unwrap_wrong_claimed_balance() {
        let req = Unwrap {
            claimed_old_balance: 200,
            encrypted_old_balance: 100,
            encrypted_new_balance: 60,
            amount: 40,
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::OldBalanceMismatch
        );
    }

    /// Keep 90 where 100 - 40 leaves 60.
    #[test]
    fn rejects_unwrap_inflated_new_balance() {
        let req = Unwrap {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 90,
            amount: 40,
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::NewBalanceMismatch
        );
    }

    /// Unwraps 200 from a balance of 100.
    #[test]
    fn rejects_unwrap_overdraft() {
        let req = Unwrap {
            claimed_old_balance: 100,
            encrypted_old_balance: 100,
            encrypted_new_balance: 60,
            amount: 200,
        };
        assert_eq!(
            verify_payload(&req.build()).unwrap_err(),
            GuardianError::Overdraft
        );
    }
}
