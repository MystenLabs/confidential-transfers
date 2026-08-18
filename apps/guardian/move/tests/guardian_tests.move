// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module guardian::guardian_tests;

use contra::{
    contra,
    encrypted_amount::{Self, EncryptedAmount},
    twisted_elgamal::{Self, public_key, Encryption}
};
use guardian::guardian;
use std::unit_test::{Self, assert_eq};
use sui::ristretto255;

/// A dummy token type; the registry is only exercised standalone here.
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

// Testing fixtures.
const FIXTURE_PK: vector<u8> = x"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const FIXTURE_SIG: vector<u8> =
    x"8ec888ea175d379f3b25ad71ecbdc65668e74f290027a36584eaf04ef8f710e0af226f462b6219fa0f83ed6b84b0288d56b8a18fd1a8273ebe60275a1ca6d303";
const ENC_PK: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The policy operator.
const ALICE: address = @0xA11CE;
/// A different address.
const BOB: address = @0xB0B;

/// A `TxContext` whose sender is `ALICE` (the fixture's operator).
fun alice_ctx(): TxContext {
    tx_context::new_from_hint(ALICE, 0, 0, 0, 0)
}

/// A registry with PCRs `00/01/02` operated by `ALICE`.
fun registry(): guardian::GuardianRegistry<TestCurrency> {
    let mut ctx = alice_ctx();
    guardian::new_registry_for_testing(guardian::new_pcrs(x"00", x"01", x"02"), ALICE, &mut ctx)
}

/// The issuer's `ManagementCap`, which gates `update`.
fun management_cap(): contra::ManagementCap<TestCurrency> {
    contra::new_management_cap_for_testing(&mut alice_ctx())
}

/// Check `approval` against the fixture transfer payload whose `GuardianRequest` `FIXTURE_SIG` signs
/// (generator sender/receiver pks, zero encryptions).
fun assert_fixture_transfer(
    registry: &guardian::GuardianRegistry<TestCurrency>,
    approval: guardian::GuardianApproval,
) {
    registry.assert_approval_for_testing(
        &approval,
        &contra::transfer_binding(
            public_key(ristretto255::g_generator()),
            vector[public_key(ristretto255::g_generator())],
            encrypt_zero(),
            &zero_amount(),
            &vector[zero_amount()],
        ),
    )
}

#[test]
fun policy_updates() {
    let mut policy = registry();
    let cap = management_cap();
    assert_eq!(policy.version(), 0);
    assert_eq!(policy.min_version(), 0);
    assert_eq!(policy.operator(), ALICE);

    // submit same pcrs, versions not bumped.
    policy.update(&cap, guardian::new_pcrs(x"00", x"01", x"02"), 0, ALICE);
    assert_eq!(policy.version(), 0);

    let new_pcrs = guardian::new_pcrs(x"10", x"11", x"12");
    policy.update(&cap, new_pcrs, 0, ALICE);
    assert_eq!(policy.version(), 1);
    assert_eq!(*policy.pcrs(), new_pcrs);

    // update min version
    policy.update(&cap, new_pcrs, 1, BOB);
    assert_eq!(policy.min_version(), 1);
    assert_eq!(policy.operator(), BOB);
    unit_test::destroy(policy);
    unit_test::destroy(cap);
}

#[test, expected_failure(abort_code = ::guardian::guardian::EInvalidMinVersion)]
fun min_version_cannot_exceed_version() {
    let mut policy = registry();
    let cap = management_cap();
    policy.update(&cap, guardian::new_pcrs(x"00", x"01", x"02"), 1, ALICE);
    unit_test::destroy(policy);
    unit_test::destroy(cap);
}

#[test]
fun verify_approval_accepts_valid_signature() {
    let mut policy = registry();
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    assert_fixture_transfer(&policy, guardian::new_guardian_approval(0, FIXTURE_SIG));
    unit_test::destroy(policy);
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun verify_approval_rejects_wrong_payload() {
    let mut policy = registry();
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    policy.assert_approval_for_testing(
        &guardian::new_guardian_approval(0, FIXTURE_SIG),
        &contra::transfer_binding(
            public_key(ristretto255::g_generator()),
            vector[], // no receiver changes payload
            encrypt_zero(),
            &zero_amount(),
            &vector[],
        ),
    );
    unit_test::destroy(policy);
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalKeyNotRegistered)]
fun verify_approval_rejects_unknown_key() {
    let policy = registry();
    assert_fixture_transfer(&policy, guardian::new_guardian_approval(0, FIXTURE_SIG));
    unit_test::destroy(policy);
}

#[test]
fun verify_approval_accepts_key_after_routine_pcr_update() {
    let mut policy = registry();
    let cap = management_cap();
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    policy.update(&cap, guardian::new_pcrs(x"10", x"11", x"12"), 0, ALICE);
    assert_fixture_transfer(&policy, guardian::new_guardian_approval(0, FIXTURE_SIG));
    unit_test::destroy(policy);
    unit_test::destroy(cap);
}

#[test]
fun operator_can_remove_key() {
    let mut policy = registry();
    let index = policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    assert!(policy.contains_guardian_enclave_key(index));

    let ctx = alice_ctx();
    policy.remove_enclave(index, &ctx);
    assert!(!policy.contains_guardian_enclave_key(index));
    unit_test::destroy(policy);
}

#[test, expected_failure(abort_code = ::guardian::guardian::ENotOperator)]
fun non_operator_cannot_remove_key() {
    let mut policy = registry();
    let index = policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    let ctx = tx_context::dummy(); // sender @0x0 != operator ALICE
    policy.remove_enclave(index, &ctx);
    unit_test::destroy(policy);
}

#[test]
fun operator_can_update_url() {
    let mut policy = registry();
    let ctx = alice_ctx();
    policy.set_url(b"https://example.com".to_string(), &ctx);
    assert_eq!(*policy.url(), b"https://example.com".to_string());
    unit_test::destroy(policy);
}

#[test, expected_failure(abort_code = ::guardian::guardian::ENotOperator)]
fun non_operator_cannot_update_url() {
    let mut policy = registry();
    let ctx = tx_context::dummy(); // not ALICE
    policy.set_url(b"x".to_string(), &ctx);
    unit_test::destroy(policy);
}

#[test]
fun min_version_bump_prunes_stale_keys() {
    let mut policy = registry();
    let cap = management_cap();
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
    policy.update(&cap, guardian::new_pcrs(x"10", x"11", x"12"), 0, ALICE);
    let slot_b = policy.register_guardian_enclave_key_for_testing(key_b, ENC_PK);

    // update to key_c
    policy.update(&cap, guardian::new_pcrs(x"20", x"21", x"22"), 0, ALICE);
    let slot_c = policy.register_guardian_enclave_key_for_testing(key_c, ENC_PK);

    // update min_version 0->2
    policy.update(&cap, guardian::new_pcrs(x"20", x"21", x"22"), 2, ALICE);

    // only key_c survived
    assert!(!policy.contains_guardian_enclave_key(slot_fixture));
    assert!(!policy.contains_guardian_enclave_key(slot_a));
    assert!(!policy.contains_guardian_enclave_key(slot_b));
    assert!(policy.contains_guardian_enclave_key(slot_c));

    // update min_version 2->0, still only key_c
    policy.update(&cap, guardian::new_pcrs(x"20", x"21", x"22"), 0, ALICE);
    assert!(!policy.contains_guardian_enclave_key(slot_fixture));
    assert!(policy.contains_guardian_enclave_key(slot_c));
    unit_test::destroy(policy);
    unit_test::destroy(cap);
}

#[test]
fun parse_user_data_round_trips() {
    let mut user_data = FIXTURE_PK;
    user_data.append(ENC_PK);
    let (signing_pk, enc_pk) = guardian::parse_user_data_for_testing(user_data);
    assert_eq!(signing_pk, FIXTURE_PK);
    assert_eq!(enc_pk, ENC_PK);
}

#[test]
fun transfer_binding_serde() {
    let payload = contra::transfer_binding(
        public_key(ristretto255::g_generator()),
        vector[public_key(ristretto255::g_generator())],
        encrypt_zero(),
        &zero_amount(),
        &vector[zero_amount()],
    );
    assert_eq!(
        std::bcs::to_bytes(&payload),
        x"0020e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d760120e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d7620000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
    );
}

// The message the enclave signs for the fixture transfer: `REQUEST_VERSION` then the blake2b256
// digest of the BCS payload — the bytes `FIXTURE_SIG` was produced over.
#[test]
fun guardian_request_serde() {
    let payload = contra::transfer_binding(
        public_key(ristretto255::g_generator()),
        vector[public_key(ristretto255::g_generator())],
        encrypt_zero(),
        &zero_amount(),
        &vector[zero_amount()],
    );
    assert_eq!(
        std::bcs::to_bytes(&guardian::new_guardian_request(&payload)),
        x"0100206f1293ccc2ff71ff4e9ee299e2cabf80e470781c357e1f4cbcb0c3d904debc7a",
    );
}

#[test]
fun unwrap_binding_serde() {
    let payload = contra::unwrap_binding(
        public_key(ristretto255::g_generator()),
        encrypt_zero(),
        &zero_amount(),
        42,
    );
    assert_eq!(
        std::bcs::to_bytes(&payload),
        x"0120e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d762000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002a00000000000000",
    );
}

#[test, expected_failure(abort_code = ::guardian::guardian::EInvalidUserData)]
fun parse_user_data_rejects_wrong_length() {
    let mut user_data = FIXTURE_PK;
    user_data.append(ENC_PK);
    user_data.push_back(0);
    guardian::parse_user_data_for_testing(user_data);
}

#[test, expected_failure(abort_code = ::guardian::guardian::EInvalidKeyLength)]
fun approval_rejects_short_signature() {
    guardian::new_guardian_approval(0, x"bb");
}

#[test, expected_failure(abort_code = ::guardian::guardian::ETooManyGuardianEnclaveKeys)]
fun registration_rejects_11th_key() {
    let mut policy = registry();
    11u8.do!(|i| {
        let mut signing_pk = ENC_PK;
        *(&mut signing_pk[0]) = i;
        policy.register_guardian_enclave_key_for_testing(signing_pk, ENC_PK);
    });
    unit_test::destroy(policy);
}

#[test]
fun registration_uses_lowest_emptied_slot() {
    let mut policy = registry();
    assert_eq!(policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK), 0);
    assert_eq!(policy.register_guardian_enclave_key_for_testing(ENC_PK, ENC_PK), 1);
    let ctx = alice_ctx();
    policy.remove_enclave(0, &ctx);
    assert_eq!(policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK), 0);
    assert!(policy.contains_guardian_enclave_key(1));
    unit_test::destroy(policy);
}
