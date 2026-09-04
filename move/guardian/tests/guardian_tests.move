// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Unit tests for the canonical Guardian package.
#[test_only]
module guardian::guardian_tests;

use contra::{
    authority,
    contra,
    encrypted_amount::{Self, EncryptedAmount},
    twisted_elgamal::{Self, public_key, Encryption}
};
use guardian::guardian;
use std::unit_test::{Self, assert_eq};
use sui::{event, ristretto255};

/// A dummy token type; the Guardian is only exercised standalone here.
public struct TestCurrency has drop {}

/// The trivial encryption of zero: `(identity, identity)`.
fun encrypt_zero(): Encryption {
    twisted_elgamal::new(ristretto255::g_identity(), ristretto255::g_identity())
}

/// An `EncryptedAmount` of four zero limbs; its collapse is `encrypt_zero()`.
fun zero_amount(): EncryptedAmount {
    encrypted_amount::new_encrypted_amount(
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    )
}

/// An encryption whose two points are distinct generator multiples for BCS regression tests.
fun tagged_encryption(ciphertext: u64, handle: u64): Encryption {
    let generator = ristretto255::g_generator();
    twisted_elgamal::new(
        ristretto255::g_mul(&ristretto255::scalar_from_u64(ciphertext), &generator),
        ristretto255::g_mul(&ristretto255::scalar_from_u64(handle), &generator),
    )
}

/// Four distinct encryptions matching the Rust `tagged_amount` fixture.
fun tagged_amount(offset: u64): EncryptedAmount {
    encrypted_amount::new_encrypted_amount(
        tagged_encryption(offset + 1, offset + 2),
        tagged_encryption(offset + 3, offset + 4),
        tagged_encryption(offset + 5, offset + 6),
        tagged_encryption(offset + 7, offset + 8),
    )
}

// Testing fixtures.
const ENCLAVE_PK: vector<u8> = x"aef3f4a4b8eca1dfc343361bf8e436bd42de9259c04b8314eb8e2054dd6e82ab";
const ENC_PK: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The Guardian operator.
const ALICE: address = @0xA11CE;
/// A different address.
const BOB: address = @0xB0B;

/// A `TxContext` whose sender is `ALICE` (the fixture's operator).
fun alice_ctx(): TxContext {
    tx_context::new_from_hint(ALICE, 0, 0, 0, 0)
}

/// A Guardian with PCRs `00/01/02` operated by `ALICE`.
fun test_guardian(): guardian::Guardian<TestCurrency> {
    let mut ctx = alice_ctx();
    let guardian = guardian::new_guardian_for_testing(
        x"00",
        x"01",
        x"02",
        ALICE,
        &mut ctx,
    );
    guardian
}

/// The issuer's `ManagementCap`, which gates `update`.
fun new_management_cap(): contra::ManagementCap<TestCurrency> {
    contra::new_management_cap_for_testing(&mut alice_ctx())
}

#[test]
fun guardian_updates() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    assert_eq!(event::events_by_type<guardian::GuardianUpdatedEvent<TestCurrency>>().length(), 1);
    assert_eq!(reg.version(), 0);
    assert_eq!(reg.min_version(), 0);
    assert_eq!(reg.operator(), ALICE);

    // submit same pcrs, versions not bumped.
    reg.update(&management_cap, x"00", x"01", x"02", 0, ALICE);
    assert_eq!(reg.version(), 0);
    assert_eq!(event::events_by_type<guardian::GuardianUpdatedEvent<TestCurrency>>().length(), 2);

    reg.update(&management_cap, x"10", x"11", x"12", 0, ALICE);
    assert_eq!(reg.version(), 1);
    let (pcr0, pcr1, pcr2) = reg.pcrs();
    assert_eq!(pcr0, x"10");
    assert_eq!(pcr1, x"11");
    assert_eq!(pcr2, x"12");
    assert_eq!(event::events_by_type<guardian::GuardianUpdatedEvent<TestCurrency>>().length(), 3);

    // update min version
    reg.update(&management_cap, x"10", x"11", x"12", 1, BOB);
    assert_eq!(reg.min_version(), 1);
    assert_eq!(reg.operator(), BOB);
    assert_eq!(event::events_by_type<guardian::GuardianUpdatedEvent<TestCurrency>>().length(), 4);
    unit_test::destroy(reg);
    unit_test::destroy(management_cap);
}

#[test, expected_failure(abort_code = ::guardian::guardian::EInvalidMinVersion)]
fun min_version_cannot_exceed_version() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    reg.update(&management_cap, x"00", x"01", x"02", 1, ALICE);
    unit_test::destroy(reg);
    unit_test::destroy(management_cap);
}

#[test]
fun operator_can_remove_key() {
    let mut reg = test_guardian();
    let index = reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    assert!(reg.contains_guardian_enclave_key(index));

    let mut ctx = alice_ctx();
    reg.remove_enclave(index, &mut ctx);
    assert!(!reg.contains_guardian_enclave_key(index));
    unit_test::destroy(reg);
}

#[test]
fun issuer_can_remove_key() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    let index = reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    reg.remove_enclave_as_issuer(&management_cap, index);
    assert!(!reg.contains_guardian_enclave_key(index));
    unit_test::destroy(reg);
    unit_test::destroy(management_cap);
}

#[test, expected_failure(abort_code = ::guardian::guardian::EEnclaveKeyNotRegistered)]
fun issuer_cannot_remove_unregistered_key() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    reg.remove_enclave_as_issuer(&management_cap, 0);
    abort
}

#[test, expected_failure(abort_code = ::guardian::guardian::EEnclaveKeyNotRegistered)]
fun issuer_cannot_remove_out_of_range_key() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    reg.remove_enclave_as_issuer(&management_cap, 64);
    abort
}

#[test, expected_failure(abort_code = ::guardian::guardian::ENotOperator)]
fun non_operator_cannot_remove_key() {
    let mut reg = test_guardian();
    let index = reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    let mut ctx = tx_context::dummy(); // sender @0x0 != operator ALICE
    reg.remove_enclave(index, &mut ctx);
    unit_test::destroy(reg);
}

#[test]
fun operator_can_update_url() {
    let mut reg = test_guardian();
    let mut ctx = alice_ctx();
    let initial_events = event::events_by_type<
        guardian::GuardianUpdatedEvent<TestCurrency>,
    >().length();
    reg.set_url(b"https://example.com".to_string(), &mut ctx);
    assert_eq!(*reg.url(), b"https://example.com".to_string());
    assert_eq!(
        event::events_by_type<guardian::GuardianUpdatedEvent<TestCurrency>>().length(),
        initial_events + 1,
    );
    unit_test::destroy(reg);
}

#[test]
fun rotated_operator_can_manage_guardian() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    let index = reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    reg.update(&management_cap, x"00", x"01", x"02", 0, BOB);

    let mut ctx = tx_context::new_from_hint(BOB, 0, 0, 0, 0);
    reg.set_url(b"https://rotated.example.com".to_string(), &mut ctx);
    reg.remove_enclave(index, &mut ctx);
    assert_eq!(*reg.url(), b"https://rotated.example.com".to_string());
    assert!(!reg.contains_guardian_enclave_key(index));
    unit_test::destroy(reg);
    unit_test::destroy(management_cap);
}

#[test, expected_failure(abort_code = ::guardian::guardian::ENotOperator)]
fun former_operator_cannot_manage_guardian() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    reg.update(&management_cap, x"00", x"01", x"02", 0, BOB);
    reg.set_url(b"x".to_string(), &mut alice_ctx());
    unit_test::destroy(reg);
    unit_test::destroy(management_cap);
}

#[test]
fun min_version_bump_prunes_stale_keys() {
    let mut reg = test_guardian();
    let management_cap = new_management_cap();
    let mut key_a = ENC_PK;
    *(&mut key_a[0]) = 0xa1;
    let mut key_b = ENC_PK;
    *(&mut key_b[0]) = 0xb1;
    let mut key_c = ENC_PK;
    *(&mut key_c[0]) = 0xc1;

    // register key_a
    let slot_fixture = reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    let slot_a = reg.register_guardian_enclave_key_for_testing(key_a, ENC_PK);

    // update to key_b
    reg.update(&management_cap, x"10", x"11", x"12", 0, ALICE);
    assert!(reg.contains_guardian_enclave_key(slot_fixture));
    assert!(reg.contains_guardian_enclave_key(slot_a));
    let slot_b = reg.register_guardian_enclave_key_for_testing(key_b, ENC_PK);

    // update to key_c
    reg.update(&management_cap, x"20", x"21", x"22", 0, ALICE);
    let slot_c = reg.register_guardian_enclave_key_for_testing(key_c, ENC_PK);

    // update min_version 0->2
    reg.update(&management_cap, x"20", x"21", x"22", 2, ALICE);

    // only key_c survived
    assert!(!reg.contains_guardian_enclave_key(slot_fixture));
    assert!(!reg.contains_guardian_enclave_key(slot_a));
    assert!(!reg.contains_guardian_enclave_key(slot_b));
    assert!(reg.contains_guardian_enclave_key(slot_c));
    assert_eq!(event::events_by_type<guardian::EnclaveRemovedEvent<TestCurrency>>().length(), 3);

    // update min_version 2->0, still only key_c
    reg.update(&management_cap, x"20", x"21", x"22", 0, ALICE);
    assert!(!reg.contains_guardian_enclave_key(slot_fixture));
    assert!(reg.contains_guardian_enclave_key(slot_c));
    assert_eq!(event::events_by_type<guardian::EnclaveRemovedEvent<TestCurrency>>().length(), 3);
    unit_test::destroy(reg);
    unit_test::destroy(management_cap);
}

#[test]
fun parse_user_data_round_trips() {
    let mut user_data = ENCLAVE_PK;
    user_data.append(ENC_PK);
    let (signing_pk, enc_pk) = guardian::parse_user_data_for_testing(user_data);
    assert_eq!(signing_pk, ENCLAVE_PK);
    assert_eq!(enc_pk, ENC_PK);
}

#[test, expected_failure(abort_code = ::guardian::guardian::EInvalidUserData)]
fun parse_user_data_rejects_wrong_length() {
    let mut user_data = ENCLAVE_PK;
    user_data.append(ENC_PK);
    user_data.push_back(0);
    guardian::parse_user_data_for_testing(user_data);
}

#[test]
fun registration_accepts_64_keys() {
    let mut reg = test_guardian();
    64u8.do!(|i| {
        let mut signing_pk = ENC_PK;
        *(&mut signing_pk[0]) = i;
        assert_eq!(reg.register_guardian_enclave_key_for_testing(signing_pk, ENC_PK), i);
    });
    unit_test::destroy(reg);
}

#[test, expected_failure(abort_code = ::guardian::guardian::ETooManyGuardianEnclaveKeys)]
fun registration_rejects_65th_key() {
    let mut reg = test_guardian();
    64u8.do!(|i| {
        let mut signing_pk = ENC_PK;
        *(&mut signing_pk[0]) = i;
        reg.register_guardian_enclave_key_for_testing(signing_pk, ENC_PK);
    });
    reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    abort
}

#[test]
fun registration_uses_lowest_emptied_slot() {
    let mut reg = test_guardian();
    assert_eq!(reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK), 0);
    assert_eq!(reg.register_guardian_enclave_key_for_testing(ENC_PK, ENC_PK), 1);
    let mut ctx = alice_ctx();
    reg.remove_enclave(0, &mut ctx);
    assert_eq!(reg.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK), 0);
    assert!(reg.contains_guardian_enclave_key(1));
    unit_test::destroy(reg);
}

/// Rust counterpart: `move_types::tests::distinct_limb_binding_regression`.
#[test]
fun distinct_limb_binding_digest_regression() {
    let payload = authority::transfer_binding(
        public_key(ristretto255::g_generator()),
        vector[public_key(ristretto255::g_generator())],
        tagged_amount(10),
        &tagged_amount(20),
        &vector[tagged_amount(30)],
    );
    assert_eq!(
        payload.digest(),
        x"92b3b166c324b7e048a4002d702051b7220bdc7a4f05b500f45dcfe92ce33e2e",
    );
}

/// Rust counterpart: `move_types::tests::guardian_request_matches_move`.
#[test]
fun guardian_request_serde() {
    let payload = authority::transfer_binding(
        public_key(ristretto255::g_generator()),
        vector[public_key(ristretto255::g_generator())],
        zero_amount(),
        &zero_amount(),
        &vector[zero_amount()],
    );
    assert_eq!(
        std::bcs::to_bytes(&guardian::new_guardian_request_for_testing(payload.digest())),
        x"01002023c5d517304afc26e1651eae6ed659d8109f14db6565420135ce9ce1ada495a3",
    );
}

/// Rust counterpart: `move_types::tests::unwrap_binding_matches_move`.
#[test]
fun unwrap_binding_digest_regression() {
    let payload = authority::unwrap_binding(
        public_key(ristretto255::g_generator()),
        zero_amount(),
        &zero_amount(),
        42,
    );
    assert_eq!(
        payload.digest(),
        x"c7955a80ffafd87ccd7f806ec2e20b80b2a14669cd8d63813d682bcff2856070",
    );
}
