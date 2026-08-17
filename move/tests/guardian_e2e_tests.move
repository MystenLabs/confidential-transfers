// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// End-to-end guardian tests transfer and unwrap flows and policy settings.
#[test_only]
module contra::guardian_e2e_tests;

use contra::{
    contra,
    contra_tests::{amount_for_testing, total_consistency_proof_for_testing},
    encrypted_amount::{Self, consistency_proof_for_testing},
    guardian,
    nizk,
    twisted_elgamal::{encrypt_trivial_for_testing, encrypt_zero, public_key}
};
use std::unit_test::{Self, assert_eq};
use sui::{coin_registry, deny_list, group_ops::Element, ristretto255};

/// `account_1`'s secret key: builds a valid balance proof.
const VALID_SK: u64 = 12345;
/// A different key (the receiver's): builds an invalid balance proof.
const INVALID_SK: u64 = 67890;

const OPERATOR: address = @0xEE;
const NEW_OPERATOR: address = @0xFF;
const GUARDIAN_ENCLAVE_PK: vector<u8> =
    x"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const GUARDED_TRANSFER_SIG: vector<u8> =
    x"7118ad4962063ce9f9bd3460ab0d361ec7ae3ade7571089c93ed0d5d6794ac3baec5c3546d4209bdfcf2c666cd4a36ac1b74a7e6f17ecbf99142380ad940c700";
// A syntactically valid (64-byte) signature that verifies under nothing.
const BAD_SIG: vector<u8> =
    x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const GUARDED_UNWRAP_SIG: vector<u8> =
    x"57dbb435c7705d49c4914f6b557f124e23323d1baf6e0e07b0cc39f1b496f71b0d10285e75f2294623c7192d5c098d786b766da4ac799556667cdf884efd9f07";

public struct TestCurrency has key { id: UID }

/// Harness setup: registries, a (optionally guarded) token, and `account_1`
/// (sk 12345, address @0x100) with 100 spendable balance.
public struct GuardedHarness {
    scenario: sui::test_scenario::Scenario,
    deny_list: deny_list::DenyList,
    acc_reg: contra::AccountRegistry,
    ct_registry: contra::TokenRegistry,
    coin_registry: coin_registry::CoinRegistry,
    builder: coin_registry::CurrencyInitializer<TestCurrency>,
    t_cap: sui::coin::TreasuryCap<TestCurrency>,
    ct: contra::ConfidentialToken<TestCurrency>,
    management_cap: contra::ManagementCap<TestCurrency>,
    account_1: contra::Account,
    pool: contra::Pool<TestCurrency>,
}

/// Sets the test guardian policy (PCRs `00/01/02`, operated by `OPERATOR`) and
/// registers the fixture enclave key at slot 0.
fun enable_test_guardian(
    ct: &mut contra::ConfidentialToken<TestCurrency>,
    management_cap: &contra::ManagementCap<TestCurrency>,
) {
    ct.set_guardian_policy<TestCurrency>(
        management_cap,
        guardian::new_pcrs(x"00", x"01", x"02"),
        OPERATOR,
    );
    ct.register_guardian_enclave_for_testing<TestCurrency>(
        GUARDIAN_ENCLAVE_PK,
        x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}

public enum Flow has copy, drop {
    Transfer,
    Unwrap,
}

/// Run a 100-wrap then 1) 50-transfer or 2) 40-unwrap depends on flow.
/// `VALID_SK` (the account's) builds the proof and `INVALID_SK` builds
/// an invalid proof.
fun run_scenario(
    flow: Flow,
    guardian_enabled: bool,
    approval: Option<guardian::GuardianApproval>,
    balance_proof_sk: u64,
) {
    let setup_addr = @0x0;
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(VALID_SK);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());

    let mut scenario = sui::test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());
    scenario.next_tx(setup_addr);
    let deny_list: deny_list::DenyList = scenario.take_shared();

    let mut acc_reg = contra::new_account_registry_for_testing(scenario.ctx());
    let mut ct_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(scenario.ctx());
    let (builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    if (guardian_enabled) enable_test_guardian(&mut ct, &management_cap);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));

    // Wrap 100 and merge: the active balance is now the trivial encryption (100*H, id).
    scenario.next_tx(addr1);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);
    scenario.next_tx(addr1);

    let mut h = GuardedHarness {
        scenario,
        deny_list,
        acc_reg,
        ct_registry,
        coin_registry,
        builder,
        t_cap,
        ct,
        management_cap,
        account_1,
        pool,
    };
    let balance_sk = ristretto255::scalar_from_u64(balance_proof_sk);
    match (flow) {
        Flow::Transfer => do_transfer(&mut h, approval, balance_sk),
        Flow::Unwrap => do_unwrap(&mut h, approval, balance_sk),
    };

    let GuardedHarness {
        scenario,
        deny_list,
        acc_reg,
        ct_registry,
        coin_registry,
        builder,
        t_cap,
        ct,
        management_cap,
        account_1,
        pool,
    } = h;
    unit_test::destroy(account_1);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);
    scenario.end();
}

/// Transfer 50 from `account_1` to a fresh receiver (`INVALID_SK`), leaving 50.
fun do_transfer(
    h: &mut GuardedHarness,
    approval: Option<guardian::GuardianApproval>,
    balance_sk: Element<ristretto255::Scalar>,
) {
    let pk_1 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(VALID_SK),
        &ristretto255::g_generator(),
    );
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(INVALID_SK),
        &ristretto255::g_generator(),
    );

    h.scenario.next_tx(addr2);
    let mut account_2 = h.acc_reg.new(addr2);
    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    account_2.register<TestCurrency>(&auth, public_key(pk_2));
    h.scenario.next_tx(@0x100);

    let r_xfer = 32533;
    let r_balance = 10097;
    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, r_balance),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let elgamal_dst = h
        .account_1
        .derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let receiver_amount = amount_for_testing(50, &pk_2, r_xfer);
    let sender_amount = amount_for_testing(50, &pk_1, r_xfer);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r_xfer, elgamal_dst);
    let old_balance = h.account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        h.account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &old_balance,
        &new_balance_ea.collapse(),
        &sender_amount.collapse(),
        &balance_sk,
    );
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 50, &receiver_amount, r_xfer, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance_ea, r_balance, &pk_1),
    ]);

    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    let ct = &h.ct;
    let deny_list = &h.deny_list;
    h
        .account_1
        .batched_transfer<TestCurrency>(
            &auth,
            ct,
            deny_list,
            vector[public_key(pk_2)],
            vector[receiver_amount],
            well_formed_proofs,
            *sender_amount.collapse().decryption_handle(),
            consistency_proof,
            ristretto255::g_identity(),
            new_balance_ea,
            sum_proof,
            option::none(),
            approval,
        )
        .add<TestCurrency>(&mut account_2, vector[], deny_list)
        .finalize();

    assert_eq!(h.account_1.balance<TestCurrency>(), new_balance_ea.collapse());
    assert_eq!(account_2.pending_encrypted_balance<TestCurrency>(), receiver_amount.collapse());
    unit_test::destroy(account_2);
}

/// Unwrap 40 from `account_1`, leaving 60.
fun do_unwrap(
    h: &mut GuardedHarness,
    approval: Option<guardian::GuardianApproval>,
    balance_sk: Element<ristretto255::Scalar>,
) {
    let pk_1 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(VALID_SK),
        &ristretto255::g_generator(),
    );

    let taken_amount = 40;
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(60, &pk_1, 76520),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let mut zero = new_balance.collapse();
    zero.add_assign_u64(taken_amount);
    zero.sub_assign(&h.account_1.balance<TestCurrency>());
    let sum_proof = nizk::zero_proof_for_testing(
        h.account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &zero,
        &balance_sk,
    );
    let elgamal_dst = h
        .account_1
        .derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let new_balance_proof = encrypted_amount::new_well_formed_proof_singleton_for_testing(
        consistency_proof_for_testing(elgamal_dst, 60, &new_balance, 76520, &pk_1),
    );
    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    let ct = &h.ct;
    let deny_list = &h.deny_list;
    let pool = &mut h.pool;
    let ctx = h.scenario.ctx();
    let coins = h
        .account_1
        .unwrap(
            &auth,
            ct,
            deny_list,
            pool,
            new_balance,
            new_balance_proof,
            taken_amount,
            &sum_proof,
            approval,
            ctx,
        );
    assert_eq!(coins.value(), 40);
    assert_eq!(h.account_1.balance<TestCurrency>(), new_balance.collapse());
    unit_test::destroy(coins);
}

#[test]
fun guardian_policy_set_update_and_unset() {
    let setup_addr = @0x0;
    let mut scenario = sui::test_scenario::begin(setup_addr);
    let ctx = &mut tx_context::dummy();
    let mut ct_registry = contra::new_token_registry_for_testing(ctx);
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(ctx);
    let (builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(8, "_", "_", "_", "_", ctx);

    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    assert!(ct.guardian_policy_for_testing<TestCurrency>().is_none());

    ct.set_guardian_policy<TestCurrency>(
        &management_cap,
        guardian::new_pcrs(x"00", x"01", x"02"),
        OPERATOR,
    );
    assert!(ct.guardian_policy_for_testing<TestCurrency>().is_some());

    assert_eq!(*ct.guardian_policy_for_testing<TestCurrency>().borrow().url(), b"".to_string());

    let operator_ctx = tx_context::new_from_hint(OPERATOR, 0, 0, 0, 0);
    ct.set_guardian_url<TestCurrency>(b"https://guardian.example.com".to_string(), &operator_ctx);
    assert_eq!(
        *ct.guardian_policy_for_testing<TestCurrency>().borrow().url(),
        b"https://guardian.example.com".to_string(),
    );
    assert_eq!(ct.guardian_policy_for_testing<TestCurrency>().borrow().operator(), OPERATOR);

    ct.update_guardian_policy<TestCurrency>(
        &management_cap,
        guardian::new_pcrs(x"10", x"11", x"12"),
        1, // min version
        NEW_OPERATOR,
    );
    let policy = ct.guardian_policy_for_testing<TestCurrency>().borrow();
    assert_eq!(policy.version(), 1);
    assert_eq!(policy.min_version(), 1);
    assert_eq!(policy.operator(), NEW_OPERATOR);

    // Unset policy.
    ct.unset_guardian_policy<TestCurrency>(&management_cap);
    assert!(ct.guardian_policy_for_testing<TestCurrency>().is_none());

    // Set policy again, version is 0.
    ct.set_guardian_policy<TestCurrency>(
        &management_cap,
        guardian::new_pcrs(x"00", x"01", x"02"),
        OPERATOR,
    );
    assert_eq!(ct.guardian_policy_for_testing<TestCurrency>().borrow().version(), 0);

    scenario.next_tx(setup_addr);
    unit_test::destroy(ct);
    unit_test::destroy(management_cap);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    scenario.end();
}

#[test, expected_failure(abort_code = ::contra::contra::EGuardianPolicyExists)]
fun guardian_policy_set_twice_errors() {
    let setup_addr = @0x0;
    let mut scenario = sui::test_scenario::begin(setup_addr);
    let ctx = &mut tx_context::dummy();
    let mut ct_registry = contra::new_token_registry_for_testing(ctx);
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(ctx);
    let (_builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        ctx,
    );
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    enable_test_guardian(&mut ct, &management_cap);

    // Second set fails
    ct.set_guardian_policy<TestCurrency>(
        &management_cap,
        guardian::new_pcrs(x"10", x"11", x"12"),
        OPERATOR,
    );
    abort
}

// === Guarded-flow tests ===
//
// Guardian enabled flow with valid approval and valid proofs passes. Guardian
// disabled with valid proof only passes.
//
// 8 tests each for either transfer or unwrap flow, 16 total:
//
// | guardian | approval           | balance proof | result                     |
// |----------|--------------------|---------------|----------------------------|
// | enabled  | valid sig          | valid         | pass                       |
// | disabled | none               | valid         | pass                       |
// | disabled | any sig (ignored)  | valid         | pass                       |
// | enabled  | none               | valid         | EApprovalMissing           |
// | enabled  | bad sig            | valid         | EApprovalSignatureMismatch |
// | enabled  | valid sig          | invalid       | EBalanceProofFailed        |
// | enabled  | bad sig            | invalid       | EApprovalSignatureMismatch |
// | enabled  | other flow's sig   | valid         | EApprovalSignatureMismatch |

#[test]
fun guardian_enabled_valid_sig_and_proofs_pass() {
    run_scenario(
        Flow::Transfer,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, GUARDED_TRANSFER_SIG)),
        VALID_SK,
    )
}

#[test]
fun guardian_enabled_valid_sig_unwrap_passes() {
    run_scenario(
        Flow::Unwrap,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, GUARDED_UNWRAP_SIG)),
        VALID_SK,
    )
}

#[test]
fun guardian_disabled_valid_proofs_pass() {
    run_scenario(
        Flow::Transfer,
        false, // guardian disabled
        option::none(),
        VALID_SK,
    )
}

#[test]
fun guardian_disabled_unwrap_passes() {
    run_scenario(
        Flow::Unwrap,
        false, // guardian disabled
        option::none(),
        VALID_SK,
    )
}

#[test]
fun guardian_disabled_ignores_approval() {
    run_scenario(
        Flow::Transfer,
        false, // guardian disabled
        option::some(guardian::new_guardian_approval(0, BAD_SIG)),
        VALID_SK,
    )
}

#[test]
fun guardian_disabled_ignores_approval_unwrap() {
    run_scenario(
        Flow::Unwrap,
        false, // guardian disabled
        option::some(guardian::new_guardian_approval(0, BAD_SIG)),
        VALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::contra::EApprovalMissing)]
fun guardian_enabled_missing_approval_fails() {
    run_scenario(
        Flow::Transfer,
        true, // guardian enabled
        option::none(),
        VALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::contra::EApprovalMissing)]
fun guardian_enabled_missing_approval_unwrap_fails() {
    run_scenario(
        Flow::Unwrap,
        true, // guardian enabled
        option::none(),
        VALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::guardian::EApprovalSignatureMismatch)]
fun guardian_enabled_invalid_sig_fails() {
    run_scenario(
        Flow::Transfer,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, BAD_SIG)),
        VALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::guardian::EApprovalSignatureMismatch)]
fun guardian_enabled_invalid_sig_unwrap_fails() {
    run_scenario(
        Flow::Unwrap,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, BAD_SIG)),
        VALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun guardian_enabled_valid_sig_invalid_proof_fails() {
    run_scenario(
        Flow::Transfer,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, GUARDED_TRANSFER_SIG)),
        INVALID_SK, // produces wrong proof
    )
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun guardian_enabled_valid_sig_invalid_proof_unwrap_fails() {
    run_scenario(
        Flow::Unwrap,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, GUARDED_UNWRAP_SIG)),
        INVALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::guardian::EApprovalSignatureMismatch)]
fun guardian_enabled_invalid_sig_and_proof_fails() {
    run_scenario(
        Flow::Transfer,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, BAD_SIG)), // bad guardian sig
        INVALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::guardian::EApprovalSignatureMismatch)]
fun guardian_enabled_invalid_sig_and_proof_unwrap_fails() {
    run_scenario(
        Flow::Unwrap,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, BAD_SIG)),
        INVALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::guardian::EApprovalSignatureMismatch)]
fun guardian_enabled_transfer_sig_cannot_approve_unwrap() {
    run_scenario(
        Flow::Unwrap,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, GUARDED_TRANSFER_SIG)),
        VALID_SK,
    )
}

#[test, expected_failure(abort_code = ::contra::guardian::EApprovalSignatureMismatch)]
fun guardian_enabled_unwrap_sig_cannot_approve_transfer() {
    run_scenario(
        Flow::Transfer,
        true, // guardian enabled
        option::some(guardian::new_guardian_approval(0, GUARDED_UNWRAP_SIG)),
        VALID_SK,
    )
}
