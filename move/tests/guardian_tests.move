// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module contra::guardian_tests;

use contra::{guardian, twisted_elgamal::encrypt_zero_for_testing};
use std::unit_test::assert_eq;
use sui::ristretto255;

// Deterministic ed25519 fixture generated with `fastcrypto::ed25519` (the same stack
// backing the on-chain verifier), seed = 0x00..1f: signature by `FIXTURE_PK` over the
// BCS bytes of `TestPayload { value: 42 }` (`2a00000000000000`).
const FIXTURE_PK: vector<u8> = x"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const FIXTURE_SIG: vector<u8> =
    x"3d5b50269e1509d49ad5fc30f438c1208d95727f6a29cb73875d8056fb712565b9f9a48cc47ecae63691856c7a3607e228cc4f0568040dbe8d6402084843c609";

const ENC_PK: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

public struct TestPayload has copy, drop { value: u64 }

fun pcrs(): guardian::Pcrs {
    guardian::new_pcrs(x"00", x"01", x"02")
}

#[test]
fun policy_defaults_and_admin_ops() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    assert_eq!(policy.version(), 0);
    assert_eq!(policy.min_version(), 0);
    assert_eq!(policy.operator(), @0x0);

    let new_pcrs = guardian::new_pcrs(x"10", x"11", x"12");
    policy.update_pcrs_for_testing(new_pcrs);
    assert_eq!(policy.version(), 1);
    assert_eq!(*policy.pcrs(), new_pcrs);
    // Existing keys are untouched by a PCR update; only min_version invalidates.
    policy.set_min_version_for_testing(1);
    assert_eq!(policy.min_version(), 1);

    policy.set_operator_for_testing(@0x1);
    assert_eq!(policy.operator(), @0x1);
}

#[test, expected_failure(abort_code = contra::guardian::EInvalidMinVersion)]
fun min_version_cannot_exceed_version() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    policy.set_min_version_for_testing(1);
}

#[test]
fun verify_approval_accepts_valid_signature() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    assert_eq!(policy.guardian_enclave_key_version_for_testing(FIXTURE_PK), 0);

    let approval = guardian::new_guardian_approval(FIXTURE_PK, FIXTURE_SIG);
    assert!(policy.verify_approval_for_testing(&approval, &TestPayload { value: 42 }));
    // Any payload divergence changes the BCS bytes and fails verification.
    assert!(!policy.verify_approval_for_testing(&approval, &TestPayload { value: 43 }));
}

#[test]
fun verify_approval_rejects_unknown_key() {
    let policy = guardian::new_for_testing(pcrs(), @0x0);
    let approval = guardian::new_guardian_approval(FIXTURE_PK, FIXTURE_SIG);
    assert!(!policy.verify_approval_for_testing(&approval, &TestPayload { value: 42 }));
}

#[test]
fun verify_approval_rejects_key_below_min_version() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);

    // A routine PCR update alone leaves the old-image key serving...
    policy.update_pcrs_for_testing(guardian::new_pcrs(x"10", x"11", x"12"));
    let approval = guardian::new_guardian_approval(FIXTURE_PK, FIXTURE_SIG);
    assert!(policy.verify_approval_for_testing(&approval, &TestPayload { value: 42 }));

    // ...until the issuer raises min_version past its registration stamp.
    policy.set_min_version_for_testing(1);
    assert!(!policy.verify_approval_for_testing(&approval, &TestPayload { value: 42 }));
}

#[test]
fun operator_can_remove_key() {
    // `tx_context::dummy()` has sender @0x0, matching the policy operator.
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    assert!(policy.contains_guardian_enclave_key(FIXTURE_PK));

    let ctx = tx_context::dummy();
    let (_, _) = policy.update_enclaves(
        option::none(),
        option::some(FIXTURE_PK),
        option::none(),
        &ctx,
    );
    assert!(!policy.contains_guardian_enclave_key(FIXTURE_PK));
}

#[test]
fun operator_can_update_url() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    let ctx = tx_context::dummy();
    let (_, _) = policy.update_enclaves(
        option::none(),
        option::none(),
        option::some(b"https://guardian.example.com".to_string()),
        &ctx,
    );
    assert_eq!(*policy.url(), b"https://guardian.example.com".to_string());
}

#[test, expected_failure(abort_code = contra::guardian::ENotOperator)]
fun non_operator_cannot_update_url() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x1);
    let ctx = tx_context::dummy(); // sender @0x0 != operator @0x1
    let (_, _) = policy.update_enclaves(
        option::none(),
        option::none(),
        option::some(b"x".to_string()),
        &ctx,
    );
}

#[test, expected_failure(abort_code = contra::guardian::ENotOperator)]
fun non_operator_cannot_remove_key() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x1);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    let ctx = tx_context::dummy(); // sender @0x0 != operator @0x1
    let (_, _) = policy.update_enclaves(
        option::none(),
        option::some(FIXTURE_PK),
        option::none(),
        &ctx,
    );
}

#[test]
fun live_guardian_enclave_keys_filters_stale_versions() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    policy.update_pcrs_for_testing(guardian::new_pcrs(x"10", x"11", x"12"));
    policy.register_guardian_enclave_key_for_testing(ENC_PK, ENC_PK); // second key, stamped v1

    assert_eq!(policy.live_guardian_enclave_keys().length(), 2);
    policy.set_min_version_for_testing(1);
    let live = policy.live_guardian_enclave_keys();
    assert_eq!(live.length(), 1);
    assert_eq!(*live[0].signing_pk().bytes(), ENC_PK);
    assert_eq!(*live[0].enc_pk().bytes(), ENC_PK);
}

#[test]
fun parse_user_data_round_trips() {
    // `user_data` is the two keys concatenated, no length prefixes.
    let mut user_data = FIXTURE_PK;
    user_data.append(ENC_PK);
    let (signing_pk, enc_pk) = guardian::parse_user_data_for_testing(user_data);
    assert_eq!(*signing_pk.bytes(), FIXTURE_PK);
    assert_eq!(*enc_pk.bytes(), ENC_PK);
}

#[test, expected_failure(abort_code = contra::guardian::EInvalidUserData)]
fun parse_user_data_rejects_wrong_length() {
    let mut user_data = FIXTURE_PK;
    user_data.append(ENC_PK);
    user_data.push_back(0);
    guardian::parse_user_data_for_testing(user_data);
}

/// Pins the BCS layout of `RequestPayload` — the enclave (guardian-core) and
/// ts-sdk must produce these exact bytes for the same inputs.
#[test]
fun request_payload_serde() {
    let payload = guardian::new_transfer_request_payload_for_testing(
        ristretto255::g_generator(),
        vector[ristretto255::g_identity()],
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        vector[encrypt_zero_for_testing()],
    );
    assert_eq!(
        std::bcs::to_bytes(&payload),
        x"0020e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d760120000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test, expected_failure(abort_code = contra::guardian::EInvalidKeyLength)]
fun approval_rejects_short_signing_pk() {
    guardian::new_guardian_approval(x"aa", FIXTURE_SIG);
}

#[test, expected_failure(abort_code = contra::guardian::EInvalidKeyLength)]
fun approval_rejects_short_signature() {
    guardian::new_guardian_approval(FIXTURE_PK, x"bb");
}

#[test, expected_failure(abort_code = contra::guardian::ETooManyGuardianEnclaveKeys)]
fun registration_rejects_eleventh_key() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    11u8.do!(|i| {
        let mut signing_pk = ENC_PK;
        *(&mut signing_pk[0]) = i;
        policy.register_guardian_enclave_key_for_testing(signing_pk, ENC_PK);
    });
}

#[test, expected_failure(abort_code = sui::vec_map::EKeyAlreadyExists)]
fun registration_rejects_duplicate_signing_pk() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
}

#[test]
fun lowering_min_version_restores_old_keys() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x0);
    policy.register_guardian_enclave_key_for_testing(FIXTURE_PK, ENC_PK);
    let approval = guardian::new_guardian_approval(FIXTURE_PK, FIXTURE_SIG);

    // Security bump revokes the v0 key; lowering the floor (rollback) restores it.
    policy.update_pcrs_for_testing(guardian::new_pcrs(x"10", x"11", x"12"));
    policy.set_min_version_for_testing(1);
    assert!(!policy.verify_approval_for_testing(&approval, &TestPayload { value: 42 }));
    policy.set_min_version_for_testing(0);
    assert!(policy.verify_approval_for_testing(&approval, &TestPayload { value: 42 }));
}

#[test]
fun update_with_all_none_is_a_noop() {
    let mut policy = guardian::new_for_testing(pcrs(), @0x1);
    policy.update(option::none(), option::none(), option::none());
    assert_eq!(policy.version(), 0);
    assert_eq!(policy.min_version(), 0);
    assert_eq!(policy.operator(), @0x1);
}

/// Pins the BCS layout of the `Unwrap` variant (tag 1).
#[test]
fun unwrap_request_payload_serde() {
    let payload = guardian::new_unwrap_request_payload_for_testing(
        ristretto255::g_generator(),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        42,
    );
    assert_eq!(
        std::bcs::to_bytes(&payload),
        x"0120e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d762000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000002a00000000000000",
    );
}
