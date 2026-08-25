use super::*;
use crate::move_types::MoveElement;
use crate::test_utils::{blinding, encrypt_amount, TEST_BLINDINGS};
use crate::types::Recipient;
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use fastcrypto::twisted_elgamal::Ciphertext;

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

/// A consistent recipient whose encrypted limbs encode the claimed amount for its public key.
fn recipient(receiver: u64, amount: u64) -> Recipient {
    Recipient {
        receiver_pk: pk(receiver),
        encrypted_amount: encrypt_amount(amount, &pk(receiver), TEST_BLINDINGS),
        amount,
        blinding: blinding(TEST_BLINDINGS),
    }
}

/// A transfer fixture described by plaintext values; `build` encrypts its balance limbs.
struct Transfer {
    claimed_old_balance: u64,
    old_balance_to_encrypt: u64,
    new_balance_to_encrypt: u64,
    recipients: Vec<Recipient>,
}

impl Transfer {
    fn build(self) -> UnsealedRequest {
        let x_a = sk(SENDER);
        let pk_a = PublicKey::from(&x_a);
        UnsealedRequest::TransferRequest {
            old_encrypted_balance: encrypt_amount(
                self.old_balance_to_encrypt,
                &pk_a,
                TEST_BLINDINGS,
            ),
            new_encrypted_balance: encrypt_amount(
                self.new_balance_to_encrypt,
                &pk_a,
                TEST_BLINDINGS,
            ),
            recipients: self.recipients,
            x_a,
            old_balance: self.claimed_old_balance,
        }
    }
}

/// An unwrap fixture described by plaintext values; `build` encrypts its balance limbs.
struct Unwrap {
    claimed_old_balance: u64,
    old_balance_to_encrypt: u64,
    new_balance_to_encrypt: u64,
    amount: u64,
}

impl Unwrap {
    fn build(self) -> UnsealedRequest {
        let x_a = sk(SENDER);
        let pk_a = PublicKey::from(&x_a);
        UnsealedRequest::UnwrapRequest {
            old_encrypted_balance: encrypt_amount(
                self.old_balance_to_encrypt,
                &pk_a,
                TEST_BLINDINGS,
            ),
            new_encrypted_balance: encrypt_amount(
                self.new_balance_to_encrypt,
                &pk_a,
                TEST_BLINDINGS,
            ),
            amount: self.amount,
            x_a,
            old_balance: self.claimed_old_balance,
        }
    }
}

#[test]
fn accepts_valid_transfer_and_unwrap_scenarios() {
    // Multi-recipient transfer binds the sender derived from x_a and the exact recipients.
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 50,
        recipients: vec![recipient(RECIPIENT_1, 30), recipient(RECIPIENT_2, 20)],
    }
    .build();
    let Binding::Transfer {
        sender_pk,
        receiver_pks,
        encrypted_amounts,
        ..
    } = verify_binding(&req).unwrap().0
    else {
        unreachable!("must be transfer binding")
    };
    let expected_sender_pk: MoveElement = pk(SENDER).as_point().into();
    let expected_receiver_pks: Vec<MoveElement> = [RECIPIENT_1, RECIPIENT_2]
        .map(|seed| pk(seed).as_point().into())
        .into();
    let expected_encrypted_amounts = vec![
        encrypt_amount(30, &pk(RECIPIENT_1), TEST_BLINDINGS),
        encrypt_amount(20, &pk(RECIPIENT_2), TEST_BLINDINGS),
    ];
    assert_eq!(
        bcs::to_bytes(&sender_pk).unwrap(),
        bcs::to_bytes(&expected_sender_pk).unwrap()
    );
    assert_eq!(
        bcs::to_bytes(&receiver_pks).unwrap(),
        bcs::to_bytes(&expected_receiver_pks).unwrap()
    );
    assert_eq!(
        bcs::to_bytes(&encrypted_amounts).unwrap(),
        bcs::to_bytes(&expected_encrypted_amounts).unwrap()
    );

    // Transfer to a zero-amount recipient.
    assert!(verify_binding(
        &Transfer {
            claimed_old_balance: 100,
            old_balance_to_encrypt: 100,
            new_balance_to_encrypt: 100,
            recipients: vec![recipient(RECIPIENT_1, 0)],
        }
        .build()
    )
    .is_ok());

    // Transfer amount spanning multiple u16 limbs.
    let transferred = (1 << 16) + 7;
    assert!(verify_binding(
        &Transfer {
            claimed_old_balance: 200_000,
            old_balance_to_encrypt: 200_000,
            new_balance_to_encrypt: 200_000 - transferred,
            recipients: vec![recipient(RECIPIENT_1, transferred)],
        }
        .build()
    )
    .is_ok());

    // Transfer from accumulated, non-canonical old-balance limbs.
    let x_a = sk(SENDER);
    let pk_a = PublicKey::from(&x_a);
    let encrypt_limb = |value: u64, randomness: u64| {
        let blinding = Blinding(RistrettoScalar::from(randomness));
        Ciphertext::new(
            PedersenCommitment::new(&RistrettoScalar::from(value), &blinding),
            *pk_a.as_point() * blinding.0,
        )
    };
    assert!(verify_binding(&UnsealedRequest::TransferRequest {
        old_encrypted_balance: EncryptedAmount {
            limbs: [
                encrypt_limb(65_536, TEST_BLINDINGS[0]),
                encrypt_limb(1, TEST_BLINDINGS[1]),
                encrypt_limb(0, TEST_BLINDINGS[2]),
                encrypt_limb(0, TEST_BLINDINGS[3]),
            ],
        },
        new_encrypted_balance: encrypt_amount(131_065, &pk_a, TEST_BLINDINGS),
        recipients: vec![recipient(RECIPIENT_1, 7)],
        x_a,
        old_balance: 131_072,
    })
    .is_ok());

    // Partial-balance unwrap.
    assert!(verify_binding(
        &Unwrap {
            claimed_old_balance: 100,
            old_balance_to_encrypt: 100,
            new_balance_to_encrypt: 60,
            amount: 40,
        }
        .build()
    )
    .is_ok());

    // Full-balance unwrap to zero.
    assert!(verify_binding(
        &Unwrap {
            claimed_old_balance: 100,
            old_balance_to_encrypt: 100,
            new_balance_to_encrypt: 0,
            amount: 100,
        }
        .build()
    )
    .is_ok());

    // Zero-amount unwrap leaving the balance unchanged.
    assert!(verify_binding(
        &Unwrap {
            claimed_old_balance: 100,
            old_balance_to_encrypt: 100,
            new_balance_to_encrypt: 100,
            amount: 0,
        }
        .build()
    )
    .is_ok());

    // Unwrap amount spanning multiple u16 limbs.
    let amount = (1 << 16) + 7;
    assert!(verify_binding(
        &Unwrap {
            claimed_old_balance: 200_000,
            old_balance_to_encrypt: 200_000,
            new_balance_to_encrypt: 200_000 - amount,
            amount,
        }
        .build()
    )
    .is_ok());

    // Maximum u64 balance.
    assert!(verify_binding(
        &Unwrap {
            claimed_old_balance: u64::MAX,
            old_balance_to_encrypt: u64::MAX,
            new_balance_to_encrypt: u64::MAX,
            amount: 0,
        }
        .build()
    )
    .is_ok());
}

#[test]
fn rejects_empty_transfer() {
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 100,
        recipients: vec![],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::EmptyTransfer
    );
}

#[test]
fn rejects_too_many_recipients() {
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 100,
        recipients: (0..=MAX_BATCH_RECIPIENTS)
            .map(|_| recipient(RECIPIENT_1, 0))
            .collect(),
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::TooManyRecipients(MAX_BATCH_RECIPIENTS + 1)
    );
}

#[test]
fn rejects_recipient_amount_sum_overflow() {
    let big = u64::MAX / 2 + 1;
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 100,
        recipients: vec![recipient(RECIPIENT_1, big), recipient(RECIPIENT_2, big)],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::TransferAmountOverflow
    );
}

#[test]
fn rejects_balance_encrypted_to_another_key() {
    let other_account_pk = pk(ATTACKER);
    let req = UnsealedRequest::TransferRequest {
        old_encrypted_balance: encrypt_amount(100, &other_account_pk, TEST_BLINDINGS),
        new_encrypted_balance: encrypt_amount(50, &other_account_pk, TEST_BLINDINGS),
        recipients: vec![recipient(RECIPIENT_1, 50)],
        x_a: sk(SENDER), // Not the key under which the balances were encrypted.
        old_balance: 100,
    };
    assert_eq!(
        verify_binding(&req).unwrap_err(),
        GuardianError::BalanceMismatch
    );
}

#[test]
fn rejects_claimed_old_balance_not_matching_encrypted_balance() {
    let req = Transfer {
        claimed_old_balance: 200, // encrypted old balance is 100
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 50,
        recipients: vec![recipient(RECIPIENT_1, 150)],
    }
    .build();
    assert_eq!(
        verify_binding(&req).unwrap_err(),
        GuardianError::BalanceMismatch
    );
}

#[test]
fn rejects_incorrect_second_old_balance_limb() {
    let req = Unwrap {
        claimed_old_balance: 2 << 16,
        old_balance_to_encrypt: 1 << 16, // claimed old balance is 2 << 16
        new_balance_to_encrypt: 0,
        amount: 2 << 16,
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::BalanceMismatch
    );
}

#[test]
fn rejects_transfer_and_unwrap_overdrafts() {
    let req = Transfer {
        claimed_old_balance: 10,
        old_balance_to_encrypt: 10,
        new_balance_to_encrypt: 0,
        recipients: vec![recipient(RECIPIENT_1, 30)], // old balance is 10
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::Overdraft
    );

    let req = Unwrap {
        claimed_old_balance: 10,
        old_balance_to_encrypt: 10,
        new_balance_to_encrypt: 0,
        amount: 30,
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::Overdraft
    );
}

#[test]
fn rejects_amount_not_matching_its_ciphertext() {
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 50,
        recipients: vec![
            recipient(RECIPIENT_1, 30),
            Recipient {
                receiver_pk: pk(RECIPIENT_2),
                encrypted_amount: encrypt_amount(19, &pk(RECIPIENT_2), TEST_BLINDINGS), // amount claims 20
                amount: 20,
                blinding: blinding(TEST_BLINDINGS),
            },
        ],
    };
    let error = verify_binding(&req.build()).unwrap_err();
    assert_eq!(
        error,
        GuardianError::RecipientAmountMismatch { recipient: 1 }
    );
    assert_eq!(
        error.to_string(),
        "encrypted amount mismatch at recipient 1"
    );
}

#[test]
fn rejects_incorrect_ciphertext_or_blinding_for_second_amount_limb() {
    let req = Transfer {
        claimed_old_balance: 3 << 16,
        old_balance_to_encrypt: 3 << 16,
        new_balance_to_encrypt: 2 << 16,
        recipients: vec![Recipient {
            receiver_pk: pk(RECIPIENT_1),
            encrypted_amount: encrypt_amount(2 << 16, &pk(RECIPIENT_1), TEST_BLINDINGS), // amount claims 1 << 16
            amount: 1 << 16,
            blinding: blinding(TEST_BLINDINGS),
        }],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::RecipientAmountMismatch { recipient: 0 }
    );

    let mut incorrect_blindings = TEST_BLINDINGS;
    incorrect_blindings[1] += 1; // ciphertext uses TEST_BLINDINGS
    let req = Transfer {
        claimed_old_balance: 2 << 16,
        old_balance_to_encrypt: 2 << 16,
        new_balance_to_encrypt: 1 << 16,
        recipients: vec![Recipient {
            receiver_pk: pk(RECIPIENT_1),
            encrypted_amount: encrypt_amount(1 << 16, &pk(RECIPIENT_1), TEST_BLINDINGS),
            amount: 1 << 16,
            blinding: blinding(incorrect_blindings),
        }],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::RecipientAmountMismatch { recipient: 0 }
    );
}

#[test]
fn rejects_amount_encrypted_to_the_wrong_recipient() {
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 50,
        recipients: vec![
            Recipient {
                receiver_pk: pk(RECIPIENT_1),
                encrypted_amount: encrypt_amount(30, &pk(ATTACKER), TEST_BLINDINGS), // encrypted to attacker
                amount: 30,
                blinding: blinding(TEST_BLINDINGS),
            },
            recipient(RECIPIENT_2, 20),
        ],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::RecipientAmountMismatch { recipient: 0 }
    );
}

#[test]
fn recipient_amount_mismatch_precedes_new_balance_mismatch() {
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 50, // should be 40 based on the claimed amount
        recipients: vec![Recipient {
            receiver_pk: pk(RECIPIENT_1),
            encrypted_amount: encrypt_amount(50, &pk(RECIPIENT_1), TEST_BLINDINGS),
            amount: 60, // encrypted amount is 50
            blinding: blinding(TEST_BLINDINGS),
        }],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::RecipientAmountMismatch { recipient: 0 }
    );
}

#[test]
fn rejects_incorrect_transfer_and_unwrap_new_balances() {
    let req = Transfer {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 80, // should be 50
        recipients: vec![recipient(RECIPIENT_1, 30), recipient(RECIPIENT_2, 20)],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::BalanceMismatch
    );

    let req = Transfer {
        claimed_old_balance: 2 << 16,
        old_balance_to_encrypt: 2 << 16,
        new_balance_to_encrypt: 3 << 16, // should be 2 << 16
        recipients: vec![recipient(RECIPIENT_1, 0)],
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::BalanceMismatch
    );

    let req = Unwrap {
        claimed_old_balance: 100,
        old_balance_to_encrypt: 100,
        new_balance_to_encrypt: 70, // should be 60
        amount: 40,
    };
    assert_eq!(
        verify_binding(&req.build()).unwrap_err(),
        GuardianError::BalanceMismatch
    );
}
