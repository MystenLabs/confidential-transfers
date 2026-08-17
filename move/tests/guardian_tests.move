// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module contra::guardian_tests;

use contra::{guardian, twisted_elgamal::{encrypt_zero_for_testing, public_key}};
use std::unit_test::assert_eq;
use sui::ristretto255;

// Testing fixtures.
const FIXTURE_PK: vector<u8> = x"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const FIXTURE_SIG: vector<u8> =
    x"23f47241711e49ff408c8a50cdb06e90178ee9f7b555cdc4b745a59c1c0be8e7f796cb0c27fa3cb1e13bdb3fe50e5659a688c34895e55ac4774be2aceebaf50a";
const ENC_PK: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The policy operator.
const ALICE: address = @0xA11CE;
/// A different address.
const BOB: address = @0xB0B;

/// A `TxContext` whose sender is the operator `ALICE`.
fun alice_ctx(): TxContext {
    tx_context::new_from_hint(ALICE, 0, 0, 0, 0)
}

/// Check `approval` against the fixture transfer payload `FIXTURE_SIG` signs
/// (generator sender/receiver pks, zero encryptions).
fun assert_fixture_transfer(
    policy: &guardian::GuardianPolicy,
    approval: guardian::GuardianApproval,
) {
    policy.assert_transfer_approval(
        &approval,
        public_key(ristretto255::g_generator()),
        vector[public_key(ristretto255::g_generator())],
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        vector[encrypt_zero_for_testing()],
    )
}

#[test]
fun policy_updates() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    assert_eq!(policy.version(), 0);
    assert_eq!(policy.min_version(), 0);
    assert_eq!(policy.operator(), ALICE);

    // submit same pcrs, versions not bumped.
    let pruned = policy.update(guardian::new_pcrs(x"00", x"01", x"02"), 0, ALICE);
    assert_eq!(pruned.length(), 0);
    assert_eq!(policy.version(), 0);

    let new_pcrs = guardian::new_pcrs(x"10", x"11", x"12");
    let _ = policy.update(new_pcrs, 0, ALICE);
    assert_eq!(policy.version(), 1);
    assert_eq!(*policy.pcrs(), new_pcrs);

    // update min version
    let _ = policy.update(new_pcrs, 1, BOB);
    assert_eq!(policy.min_version(), 1);
    assert_eq!(policy.operator(), BOB);
}

#[test, expected_failure(abort_code = contra::guardian::EInvalidMinVersion)]
fun min_version_cannot_exceed_version() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    let _ = policy.update(guardian::new_pcrs(x"00", x"01", x"02"), 1, ALICE);
}

#[test]
fun verify_approval_accepts_valid_signature() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    assert_fixture_transfer(&policy, guardian::new_guardian_approval(0, FIXTURE_SIG));
}

#[test, expected_failure(abort_code = contra::guardian::EApprovalSignatureMismatch)]
fun verify_approval_rejects_wrong_payload() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    policy.assert_transfer_approval(
        &guardian::new_guardian_approval(0, FIXTURE_SIG),
        public_key(ristretto255::g_generator()),
        vector[], // no receiver changes payload
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        vector[],
    );
}

#[test, expected_failure(abort_code = contra::guardian::EApprovalKeyNotRegistered)]
fun verify_approval_rejects_unknown_key() {
    let policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    assert_fixture_transfer(&policy, guardian::new_guardian_approval(0, FIXTURE_SIG));
}

#[test]
fun verify_approval_accepts_key_after_routine_pcr_update() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    let _ = policy.update(guardian::new_pcrs(x"10", x"11", x"12"), 0, ALICE);
    assert_fixture_transfer(&policy, guardian::new_guardian_approval(0, FIXTURE_SIG));
}

#[test]
fun operator_can_remove_key() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    let index = policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    assert!(policy.contains_guardian_enclave_key(index));

    let ctx = alice_ctx();
    policy.remove_enclave(index, &ctx);
    assert!(!policy.contains_guardian_enclave_key(index));
}

#[test, expected_failure(abort_code = contra::guardian::ENotOperator)]
fun non_operator_cannot_remove_key() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    let index = policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    let ctx = tx_context::dummy(); // sender @0x0 != operator ALICE
    policy.remove_enclave(index, &ctx);
}

#[test]
fun operator_can_update_url() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    let ctx = alice_ctx();
    policy.set_url(b"https://example.com".to_string(), &ctx);
    assert_eq!(*policy.url(), b"https://example.com".to_string());
}

#[test, expected_failure(abort_code = contra::guardian::ENotOperator)]
fun non_operator_cannot_update_url() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    let ctx = tx_context::dummy(); // not ALICE
    policy.set_url(b"x".to_string(), &ctx);
}

#[test]
fun min_version_bump_prunes_stale_keys() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    let mut key_a = ENC_PK;
    *(&mut key_a[0]) = 0xa1;
    let mut key_b = ENC_PK;
    *(&mut key_b[0]) = 0xb1;
    let mut key_c = ENC_PK;
    *(&mut key_c[0]) = 0xc1;

    // register key_a
    let slot_fixture = policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    let slot_a = policy.register_guardian_enclave_key_for_testing(key_a, ENC_PK);

    // update to key_b
    let _ = policy.update(guardian::new_pcrs(x"10", x"11", x"12"), 0, ALICE);
    let slot_b = policy.register_guardian_enclave_key_for_testing(key_b, ENC_PK);

    // update to key_c
    let _ = policy.update(guardian::new_pcrs(x"20", x"21", x"22"), 0, ALICE);
    let slot_c = policy.register_guardian_enclave_key_for_testing(key_c, ENC_PK);

    // update min_version 0->2
    let pruned = policy.update(guardian::new_pcrs(x"20", x"21", x"22"), 2, ALICE);
    assert_eq!(pruned.length(), 3);

    // only key_c survived
    assert!(!policy.contains_guardian_enclave_key(slot_fixture));
    assert!(!policy.contains_guardian_enclave_key(slot_a));
    assert!(!policy.contains_guardian_enclave_key(slot_b));
    assert!(policy.contains_guardian_enclave_key(slot_c));

    // update min_version 2->0, still only key_c
    let _ = policy.update(guardian::new_pcrs(x"20", x"21", x"22"), 0, ALICE);
    assert!(!policy.contains_guardian_enclave_key(slot_fixture));
    assert!(policy.contains_guardian_enclave_key(slot_c));
}

#[test]
fun parse_user_data_round_trips() {
    let mut user_data = FIXTURE_PK;
    user_data.append(ENC_PK);
    let (signing_pk, enc_pk) = guardian::parse_user_data(user_data);
    assert_eq!(*signing_pk.bytes(), FIXTURE_PK);
    assert_eq!(*enc_pk.bytes(), ENC_PK);
}

#[test]
fun transfer_request_payload_serde() {
    let payload = guardian::new_transfer_request_payload(
        public_key(ristretto255::g_generator()),
        vector[public_key(ristretto255::g_generator())],
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        vector[encrypt_zero_for_testing()],
    );
    assert_eq!(
        std::bcs::to_bytes(&payload),
        x"0020e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d760120e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d7620000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fun unwrap_request_payload_serde() {
    let payload = guardian::new_unwrap_request_payload(
        public_key(ristretto255::g_generator()),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        42,
    );
    assert_eq!(
        std::bcs::to_bytes(&payload),
        x"0120e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d762000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002a00000000000000",
    );
}

#[test, expected_failure(abort_code = contra::guardian::EInvalidUserData)]
fun parse_user_data_rejects_wrong_length() {
    let mut user_data = FIXTURE_PK;
    user_data.append(ENC_PK);
    user_data.push_back(0);
    guardian::parse_user_data(user_data);
}

#[test, expected_failure(abort_code = contra::guardian::EInvalidKeyLength)]
fun approval_rejects_short_signature() {
    guardian::new_guardian_approval(0, x"bb");
}

#[test, expected_failure(abort_code = contra::guardian::ETooManyGuardianEnclaveKeys)]
fun registration_rejects_11th_key() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    11u8.do!(|i| {
        let mut signing_pk = ENC_PK;
        *(&mut signing_pk[0]) = i;
        policy.register_guardian_enclave_key_for_testing(signing_pk, ENC_PK);
    });
}

#[test]
fun registration_uses_lowest_emptied_slot() {
    let mut policy = guardian::new(guardian::new_pcrs(x"00", x"01", x"02"), ALICE);
    assert_eq!(policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK), 0);
    assert_eq!(policy.register_guardian_enclave_key_for_testing(ENC_PK, ENC_PK), 1);
    let ctx = alice_ctx();
    policy.remove_enclave(0, &ctx);
    assert_eq!(policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK), 0);
    assert!(policy.contains_guardian_enclave_key(1));
}
