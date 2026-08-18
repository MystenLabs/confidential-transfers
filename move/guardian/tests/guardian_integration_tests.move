// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Integration tests for the canonical Guardian package and Contra protected operations.
#[test_only]
module guardian::guardian_integration_tests;

use contra::{
    authority::{Self, Approval},
    contra,
    encrypted_amount::{
        Self,
        EncryptedAmount,
        consistency_proof_for_testing,
        sender_consistency_proof_for_testing,
    },
    events::{AuthorityDisabledEvent, AuthorityEnabledEvent},
    nizk,
    range_proof,
    twisted_elgamal::{Self, encrypt_trivial_for_testing, public_key}
};
use guardian::{custom_authority_for_testing, guardian};
use std::unit_test::{Self, assert_eq};
use sui::{coin_registry, deny_list, event, group_ops::Element, ristretto255::{Self, G}};

/// `account_1`'s secret key: builds a valid balance proof.
const VALID_SK: u64 = 12345;
/// A different key that builds an invalid balance proof.
const INVALID_SK: u64 = 67890;
/// A third receiver key used to change an otherwise-valid transfer after approval.
const TAMPERED_RECEIVER_SK: u64 = 24680;

/// The sender (`account_1`) address.
const SENDER: address = @0x100;
/// The receiver (`account_2`) address.
const RECEIVER: address = @0x101;
/// The Guardian operator.
const ALICE: address = @0xA11CE;

/// The fixture enclave key generated after the HPKE key from an all-zero RNG seed, and its
/// signatures over the `GuardianRequest` for the harness's 50-transfer and 40-unwrap.
const ENCLAVE_PK: vector<u8> = x"aef3f4a4b8eca1dfc343361bf8e436bd42de9259c04b8314eb8e2054dd6e82ab";
const ENC_PK: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRANSFER_SIG: vector<u8> =
    x"663dee617bacd7dac45afb4b1e0f5abe689ecfad9ec841a258daf7d3bc25a6f149e9d29ae2c61965dc030358d69b1699d5fb46c010f6fc81bdd8b40914009d0b";
const UNWRAP_SIG: vector<u8> =
    x"91797d0f540182a08e3145fe7d3b24b5709950dce566a922952726378f4de25d80dd1e108b3209a60067cb6d4082d962f7c55b6fc3c0a3c5e2d198ef02cda50a";
const BAD_SIG: vector<u8> =
    x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// The 50-transfer's blindings: the receiver amount / total (`TRANSFER_R`) and the sender's new
/// balance (`TRANSFER_BALANCE_R`).
const TRANSFER_R: u64 = 32533;
const TRANSFER_BALANCE_R: u64 = 10097;

/// The 40-unwrap's amount and the blinding of the sender's new balance.
const UNWRAP_AMOUNT: u64 = 40;
const UNWRAP_R: u64 = 76520;

public struct TestCurrency has key { id: UID }

/// Registries, a token, and `account_1` (`SENDER`, sk `VALID_SK`) holding 100 spendable.
public struct Harness {
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

// === Cryptographic fixtures ===

/// `account_1`'s public key (`VALID_SK * G`).
fun pk_1(): Element<G> {
    ristretto255::g_mul(&ristretto255::scalar_from_u64(VALID_SK), &ristretto255::g_generator())
}

/// The receiver's public key (`INVALID_SK * G`).
fun pk_2(): Element<G> {
    ristretto255::g_mul(&ristretto255::scalar_from_u64(INVALID_SK), &ristretto255::g_generator())
}

/// The trivial encryption of zero: `(identity, identity)`.
fun encrypt_zero(): twisted_elgamal::Encryption {
    twisted_elgamal::new(ristretto255::g_identity(), ristretto255::g_identity())
}

/// A single-value `EncryptedAmount` (`value` in limb 0, zero elsewhere) under `pk`, with limb 0
/// encrypted using blinding `r`.
fun amount_for_testing(value: u16, pk: &Element<G>, r: u64): EncryptedAmount {
    encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(value as u64, pk, r),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    )
}

// === Harness lifecycle ===

/// A harness whose token initially has no external authority.
fun new_harness(): Harness {
    let setup_addr = @0x0;
    let pk_1 = pk_1();

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

    scenario.next_tx(SENDER);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    scenario.next_tx(SENDER);
    let mut account_1 = acc_reg.new(SENDER);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));

    // Wrap 100 and merge: the active balance is now the trivial encryption (100*H, id).
    scenario.next_tx(SENDER);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);
    scenario.next_tx(SENDER);

    Harness {
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
    }
}

fun destroy(h: Harness) {
    let Harness {
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

// === Protected operation execution ===

/// Transfer 50 from `account_1` to a fresh receiver (`RECEIVER`, sk `INVALID_SK`) with `approval`
/// and check both balances moved. `balance_proof_sk` is the key the balance ZK proof is built
/// with: `VALID_SK` makes it valid; `INVALID_SK` breaks only the proof.
fun execute_fixture_transfer(
    h: &mut Harness,
    balance_proof_sk: u64,
    approval: Option<Approval<TestCurrency>>,
) {
    execute_transfer_with_inputs(
        h,
        balance_proof_sk,
        INVALID_SK,
        50,
        TRANSFER_R,
        50,
        TRANSFER_BALANCE_R,
        approval,
    )
}

/// Execute a valid transfer with explicit receiver and balance values so approval-binding fields
/// can be changed independently of the ZK proofs.
fun execute_transfer_with_inputs(
    h: &mut Harness,
    balance_proof_sk: u64,
    receiver_sk: u64,
    amount: u16,
    receiver_r: u64,
    new_balance_value: u16,
    new_balance_r: u64,
    approval: Option<Approval<TestCurrency>>,
) {
    let pk_1 = pk_1();
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(receiver_sk),
        &ristretto255::g_generator(),
    );
    let receiver_amount = amount_for_testing(amount, &pk_2, receiver_r);
    let new_balance = amount_for_testing(new_balance_value, &pk_1, new_balance_r);

    h.scenario.next_tx(RECEIVER);
    let mut account_2 = h.acc_reg.new(RECEIVER);
    let receiver_auth = h.ct.authorize_as_sender(h.scenario.ctx());
    account_2.register<TestCurrency>(&receiver_auth, public_key(pk_2));
    h.scenario.next_tx(SENDER);

    let elgamal_dst = h.account_1.dst_elgamal_for_testing<TestCurrency>();
    let receiver_consistency_proof = consistency_proof_for_testing(
        elgamal_dst,
        amount,
        &receiver_amount,
        receiver_r,
        &pk_2,
    );
    // The sender-side total: same commitment as the receiver amount, handle under `pk_1`.
    let total_sender = amount_for_testing(amount, &pk_1, receiver_r).collapse_for_testing();
    let sender_consistency_proof = sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance,
        new_balance_value,
        new_balance_r,
        &total_sender,
        amount as u64,
        receiver_r,
        &pk_1,
    );
    let balance_proof = nizk::sum_proof_for_testing(
        h.account_1.dst_ddh_for_testing<TestCurrency>(),
        &h.account_1.balance<TestCurrency>(),
        &new_balance.collapse_for_testing(),
        &total_sender,
        &ristretto255::scalar_from_u64(balance_proof_sk),
    );

    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    h
        .account_1
        .batched_transfer<TestCurrency>(
            &auth,
            &h.ct,
            &h.deny_list,
            vector[public_key(pk_2)],
            vector[receiver_amount],
            vector[receiver_consistency_proof],
            new_balance,
            twisted_elgamal::decryption_handle_for_testing(&total_sender),
            sender_consistency_proof,
            range_proof::new_range_proof_for_testing(),
            ristretto255::g_identity(),
            balance_proof,
            option::none(),
            approval,
        )
        .add<TestCurrency>(&mut account_2, vector[], &h.deny_list)
        .finalize();

    assert_eq!(h.account_1.balance<TestCurrency>(), new_balance.collapse_for_testing());
    assert_eq!(
        account_2.pending_encrypted_balance<TestCurrency>(),
        receiver_amount.collapse_for_testing(),
    );
    unit_test::destroy(account_2);
}

/// Unwrap 40 from `account_1` with `approval` and check the coin and balance. `balance_proof_sk`
/// as in `execute_transfer`.
fun execute_fixture_unwrap(
    h: &mut Harness,
    balance_proof_sk: u64,
    approval: Option<Approval<TestCurrency>>,
) {
    execute_unwrap_with_inputs(h, balance_proof_sk, 60, UNWRAP_R, UNWRAP_AMOUNT, approval)
}

/// Execute a valid unwrap with explicit amount and new balance so each approval-binding field can
/// be changed independently of the ZK proofs.
fun execute_unwrap_with_inputs(
    h: &mut Harness,
    balance_proof_sk: u64,
    new_balance_value: u16,
    new_balance_r: u64,
    amount: u64,
    approval: Option<Approval<TestCurrency>>,
) {
    let pk_1 = pk_1();
    let new_balance = amount_for_testing(new_balance_value, &pk_1, new_balance_r);
    // `new_balance + amount - old_balance`: the old balance is the trivial `(100*H, id)`, so this
    // is the blinding-`new_balance_r` encryption of zero under `pk_1`.
    let zero = encrypt_trivial_for_testing(0, &pk_1, new_balance_r);
    let balance_proof = nizk::zero_proof_for_testing(
        h.account_1.dst_ddh_for_testing<TestCurrency>(),
        &zero,
        &ristretto255::scalar_from_u64(balance_proof_sk),
    );
    let new_balance_consistency_proof = consistency_proof_for_testing(
        h.account_1.dst_elgamal_for_testing<TestCurrency>(),
        new_balance_value,
        &new_balance,
        new_balance_r,
        &pk_1,
    );
    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    let ctx = h.scenario.ctx();
    let coins = h
        .account_1
        .unwrap(
            &auth,
            &h.ct,
            &h.deny_list,
            &mut h.pool,
            new_balance,
            new_balance_consistency_proof,
            range_proof::new_range_proof_for_testing(),
            amount,
            &balance_proof,
            approval,
            ctx,
        );
    assert_eq!(coins.value(), amount);
    assert_eq!(h.account_1.balance<TestCurrency>(), new_balance.collapse_for_testing());
    unit_test::destroy(coins);
}

/// Wrap and merge one more coin into `account_1`, changing the active balance the approval
/// committed to.
fun bump_balance(h: &mut Harness) {
    let coins = h.t_cap.mint(1, h.scenario.ctx());
    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    h.account_1.wrap(&auth, &h.ct, &h.deny_list, &h.pool, coins, vector[]);
    h.account_1.merge<TestCurrency>(&auth);
}

// === Authority fixtures ===

/// Create the Guardian derived from the harness's confidential token.
fun new_guardian(h: &mut Harness): guardian::Guardian<TestCurrency> {
    guardian::new_guardian(
        &mut h.ct,
        &h.management_cap,
        x"00",
        x"01",
        x"02",
        ALICE,
    )
}

/// A Guardian holding the fixture enclave key at slot 0.
fun new_registered_guardian(h: &mut Harness): guardian::Guardian<TestCurrency> {
    let mut guardian = new_guardian(h);
    guardian.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    guardian
}

/// Enable `guardian` as the harness token's authority.
fun enable_guardian_authority(guardian: &guardian::Guardian<TestCurrency>, h: &mut Harness) {
    guardian::enable(&mut h.ct, guardian, &h.management_cap);
}

/// The issuer disables the enabled Guardian.
fun disable_guardian_authority(guardian: &guardian::Guardian<TestCurrency>, h: &mut Harness) {
    guardian::disable(&mut h.ct, guardian, &h.management_cap);
}

/// A harness with a fixture Guardian enabled as its authority.
fun guarded_harness(): (guardian::Guardian<TestCurrency>, Harness) {
    let mut h = new_harness();
    let guardian = new_registered_guardian(&mut h);
    enable_guardian_authority(&guardian, &mut h);
    (guardian, h)
}

/// A custom authority with its own ID and privately stored authority capability.
fun new_custom_authority(
    h: &mut Harness,
): custom_authority_for_testing::CustomAuthority<TestCurrency> {
    custom_authority_for_testing::new(&h.management_cap, h.scenario.ctx())
}

/// Replace the harness token's enabled authority with `custom_authority`.
fun enable_custom_authority(
    custom_authority: &custom_authority_for_testing::CustomAuthority<TestCurrency>,
    h: &mut Harness,
) {
    custom_authority_for_testing::enable(
        &mut h.ct,
        custom_authority,
        &h.management_cap,
    );
}

/// Disable `custom_authority` for the harness token.
fun disable_custom_authority(
    custom_authority: &custom_authority_for_testing::CustomAuthority<TestCurrency>,
    h: &mut Harness,
) {
    custom_authority_for_testing::disable(
        &mut h.ct,
        custom_authority,
        &h.management_cap,
    );
}

// === Approval fixtures ===

/// Digest of the fixture's 50-transfer operation binding.
fun transfer_digest(h: &Harness): vector<u8> {
    let binding = authority::transfer_binding(
        h.account_1.token_public_key<TestCurrency>(),
        vector[public_key(pk_2())],
        h.account_1.balance_amount<TestCurrency>(),
        &amount_for_testing(50, &pk_1(), TRANSFER_BALANCE_R),
        &vector[amount_for_testing(50, &pk_2(), TRANSFER_R)],
    );
    binding.digest()
}

fun guardian_transfer_approval_at_key(
    guardian: &guardian::Guardian<TestCurrency>,
    h: &Harness,
    key_index: u8,
    sig: vector<u8>,
): Option<Approval<TestCurrency>> {
    guardian.new_approval<TestCurrency>(
        &h.ct,
        transfer_digest(h),
        key_index,
        sig,
    )
}

/// Guardian approval for the 50-transfer with the enclave signature `sig`.
fun guardian_transfer_approval(
    guardian: &guardian::Guardian<TestCurrency>,
    h: &Harness,
    sig: vector<u8>,
): Option<Approval<TestCurrency>> {
    guardian_transfer_approval_at_key(guardian, h, 0, sig)
}

/// Guardian approval for the 40-unwrap with the enclave signature `sig`.
fun guardian_unwrap_approval(
    guardian: &guardian::Guardian<TestCurrency>,
    h: &Harness,
    sig: vector<u8>,
): Option<Approval<TestCurrency>> {
    let binding = authority::unwrap_binding(
        h.account_1.token_public_key<TestCurrency>(),
        h.account_1.balance_amount<TestCurrency>(),
        &amount_for_testing(60, &pk_1(), UNWRAP_R),
        UNWRAP_AMOUNT,
    );
    guardian.new_approval<TestCurrency>(
        &h.ct,
        binding.digest(),
        0,
        sig,
    )
}

// === Guardian authority lifecycle ===

#[test]
fun guardian_can_be_created_enabled_and_shared_atomically() {
    let mut h = new_harness();
    let guardian_obj = new_guardian(&mut h);
    enable_guardian_authority(&guardian_obj, &mut h);
    guardian::share(guardian_obj);

    destroy(h);
}

#[test]
fun guardian_can_be_enabled_after_sharing() {
    let mut h = new_harness();
    let guardian_obj = new_guardian(&mut h);
    guardian::share(guardian_obj);

    h.scenario.next_tx(SENDER);
    let guardian_obj: guardian::Guardian<TestCurrency> = h.scenario.take_shared();
    enable_guardian_authority(&guardian_obj, &mut h);

    sui::test_scenario::return_shared(guardian_obj);
    destroy(h);
}

#[test]
fun guardian_planned_rotation_keeps_old_key_active() {
    let (mut guardian_obj, mut h) = guarded_harness();
    guardian_obj.update(
        &h.management_cap,
        x"10",
        x"11",
        x"12",
        0,
        ALICE,
    );
    let new_key_index = guardian_obj.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    assert!(guardian_obj.contains_guardian_enclave_key(0));
    assert!(guardian_obj.contains_guardian_enclave_key(new_key_index));

    let approval = guardian_transfer_approval_at_key(&guardian_obj, &h, 0, TRANSFER_SIG);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(guardian_obj);
}

#[test]
fun guardian_version_rotation_prunes_old_key_and_accepts_new_key() {
    let (mut guardian_obj, mut h) = guarded_harness();
    guardian_obj.update(
        &h.management_cap,
        x"10",
        x"11",
        x"12",
        0,
        ALICE,
    );
    let new_key_index = guardian_obj.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    guardian_obj.update(
        &h.management_cap,
        x"10",
        x"11",
        x"12",
        1,
        ALICE,
    );
    assert!(!guardian_obj.contains_guardian_enclave_key(0));
    assert!(guardian_obj.contains_guardian_enclave_key(new_key_index));

    let approval = guardian_transfer_approval_at_key(
        &guardian_obj,
        &h,
        new_key_index,
        TRANSFER_SIG,
    );
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(guardian_obj);
}

#[test]
fun custom_authority_can_replace_guardian_approve_and_disable() {
    let (guardian_obj, mut h) = guarded_harness();
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    assert_eq!(event::events_by_type<AuthorityEnabledEvent<TestCurrency>>().length(), 2);
    assert_eq!(event::events_by_type<AuthorityDisabledEvent<TestCurrency>>().length(), 1);

    let approval = custom_authority_for_testing::mint_approval(
        &custom_authority,
        &h.ct,
        &transfer_digest(&h),
    );
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    disable_custom_authority(&custom_authority, &mut h);
    assert_eq!(event::events_by_type<AuthorityDisabledEvent<TestCurrency>>().length(), 1);

    destroy(h);
    unit_test::destroy(guardian_obj);
    unit_test::destroy(custom_authority);
}

#[test]
fun canonical_guardian_can_replace_custom_authority() {
    let (guardian_obj, mut h) = guarded_harness();
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    enable_guardian_authority(&guardian_obj, &mut h);

    let approval = guardian_transfer_approval(&guardian_obj, &h, TRANSFER_SIG);
    execute_fixture_transfer(&mut h, VALID_SK, approval);

    destroy(h);
    unit_test::destroy(guardian_obj);
    unit_test::destroy(custom_authority);
}

#[test]
fun guardian_can_be_reenabled_after_disable() {
    let (guardian_obj, mut h) = guarded_harness();
    disable_guardian_authority(&guardian_obj, &mut h);
    enable_guardian_authority(&guardian_obj, &mut h);
    let approval = guardian_transfer_approval(&guardian_obj, &h, TRANSFER_SIG);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(guardian_obj);
}

#[test]
fun guardian_enable_and_disable_are_idempotent() {
    let (guardian_obj, mut h) = guarded_harness();
    assert_eq!(event::events_by_type<AuthorityEnabledEvent<TestCurrency>>().length(), 1);

    enable_guardian_authority(&guardian_obj, &mut h);
    assert_eq!(event::events_by_type<AuthorityEnabledEvent<TestCurrency>>().length(), 1);

    disable_guardian_authority(&guardian_obj, &mut h);
    disable_guardian_authority(&guardian_obj, &mut h);
    assert_eq!(event::events_by_type<AuthorityDisabledEvent<TestCurrency>>().length(), 1);

    destroy(h);
    unit_test::destroy(guardian_obj);
}

#[test, expected_failure(abort_code = ::sui::derived_object::EObjectAlreadyExists)]
fun guardian_can_only_be_created_once_per_confidential_token() {
    let mut h = new_harness();
    let _first = new_guardian(&mut h);
    let _second = new_guardian(&mut h);
    abort
}

#[test, expected_failure(abort_code = ::guardian::guardian::EEnclaveKeyNotRegistered)]
fun guardian_rejects_unknown_enclave_key() {
    let mut h = new_harness();
    let guardian_obj = new_guardian(&mut h);
    enable_guardian_authority(&guardian_obj, &mut h);
    let _approval = guardian_transfer_approval(&guardian_obj, &h, TRANSFER_SIG);
    abort
}

#[test, expected_failure(abort_code = ::guardian::guardian::EEnclaveKeyNotRegistered)]
fun guardian_rejects_out_of_range_enclave_key() {
    let (guardian_obj, h) = guarded_harness();
    let _approval = guardian_transfer_approval_at_key(&guardian_obj, &h, 64, TRANSFER_SIG);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EWrongAuthority)]
fun replaced_guardian_cannot_disable_custom_authority() {
    let (guardian_obj, mut h) = guarded_harness();
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    disable_guardian_authority(&guardian_obj, &mut h);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EWrongAuthority)]
fun replaced_custom_authority_cannot_mint_approval() {
    let (guardian_obj, mut h) = guarded_harness();
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    enable_guardian_authority(&guardian_obj, &mut h);
    let _approval = custom_authority_for_testing::mint_approval(
        &custom_authority,
        &h.ct,
        &transfer_digest(&h),
    );
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EWrongAuthority)]
fun replaced_guardian_cannot_mint_approval() {
    let (guardian_obj, mut h) = guarded_harness();
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    let _approval = guardian_transfer_approval(&guardian_obj, &h, TRANSFER_SIG);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EWrongAuthority)]
fun replacement_invalidates_previous_guardian_approval() {
    let (guardian_obj, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&guardian_obj, &h, TRANSFER_SIG);
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    abort
}

// === Protected operation approval matrix ===
//
// Tested operations: transfer and unwrap. TODO: add rekey and balance update.
//
// | authority state | approval                                    | balance proof | result                     |
// |-----------------|---------------------------------------------|---------------|----------------------------|
// | disabled        | approval minted before disabling            | valid         | pass (approval discarded)  |
// | disabled        | invalid Guardian signature (no-op)          | valid         | pass                       |
// | enabled         | Guardian, valid signature                   | valid         | pass                       |
// | disabled        | none                                        | invalid       | EBalanceProofFailed        |
// | enabled         | none                                        | valid         | EApprovalRequired          |
// | enabled         | Guardian, valid signature                   | invalid       | EBalanceProofFailed        |
// | enabled         | as above, but the balance moves before use  | valid         | EApprovalMismatch          |
// | enabled         | valid approval, operation arguments changed | valid         | EApprovalMismatch          |
// | enabled         | signature over the other operation          | valid         | EApprovalSignatureMismatch |
// | enabled         | Guardian approval for the other operation   | valid         | EApprovalMismatch          |
// | enabled         | bad Guardian signature                      | not reached   | EApprovalSignatureMismatch |

// --- Authority disabled or not yet enabled ---

#[test]
fun no_authority_existing_approval_transfer_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    disable_guardian_authority(&registry, &mut h);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun no_authority_existing_approval_unwrap_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_unwrap_approval(&registry, &h, UNWRAP_SIG);
    disable_guardian_authority(&registry, &mut h);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun disabled_guardian_bad_sig_transfer_passes() {
    let (registry, mut h) = guarded_harness();
    disable_guardian_authority(&registry, &mut h);
    let approval = guardian_transfer_approval(&registry, &h, BAD_SIG);
    assert!(approval.is_none());
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun disabled_guardian_bad_sig_unwrap_passes() {
    let (registry, mut h) = guarded_harness();
    disable_guardian_authority(&registry, &mut h);
    let approval = guardian_unwrap_approval(&registry, &h, BAD_SIG);
    assert!(approval.is_none());
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

// --- Guardian authority ---

#[test]
fun guardian_valid_sig_transfer_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun guardian_valid_sig_unwrap_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun no_authority_invalid_proof_transfer_fails() {
    let mut h = new_harness();
    execute_fixture_transfer(&mut h, INVALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun no_authority_invalid_proof_unwrap_fails() {
    let mut h = new_harness();
    execute_fixture_unwrap(&mut h, INVALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EApprovalRequired)]
fun guardian_missing_approval_transfer_fails() {
    let (_registry, mut h) = guarded_harness();
    execute_fixture_transfer(&mut h, VALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EApprovalRequired)]
fun guardian_missing_approval_unwrap_fails() {
    let (_registry, mut h) = guarded_harness();
    execute_fixture_unwrap(&mut h, VALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun guardian_valid_sig_invalid_proof_transfer_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_fixture_transfer(&mut h, INVALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun guardian_valid_sig_invalid_proof_unwrap_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_fixture_unwrap(&mut h, INVALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_stale_approval_transfer_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    bump_balance(&mut h);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_stale_approval_unwrap_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_unwrap_approval(&registry, &h, UNWRAP_SIG);
    bump_balance(&mut h);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_changed_transfer_receiver_key_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_transfer_with_inputs(
        &mut h,
        VALID_SK,
        TAMPERED_RECEIVER_SK,
        50,
        TRANSFER_R,
        50,
        TRANSFER_BALANCE_R,
        approval,
    );
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_changed_transfer_receiver_encryption_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_transfer_with_inputs(
        &mut h,
        VALID_SK,
        INVALID_SK,
        50,
        TRANSFER_R + 1,
        50,
        TRANSFER_BALANCE_R,
        approval,
    );
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_changed_transfer_new_balance_encryption_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_transfer_with_inputs(
        &mut h,
        VALID_SK,
        INVALID_SK,
        50,
        TRANSFER_R,
        50,
        TRANSFER_BALANCE_R + 1,
        approval,
    );
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_changed_unwrap_amount_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_unwrap_with_inputs(&mut h, VALID_SK, 59, UNWRAP_R, UNWRAP_AMOUNT + 1, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_changed_unwrap_new_balance_encryption_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_unwrap_with_inputs(
        &mut h,
        VALID_SK,
        60,
        UNWRAP_R + 1,
        UNWRAP_AMOUNT,
        approval,
    );
    abort
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun guardian_unwrap_sig_transfer_fails() {
    let (registry, h) = guarded_harness();
    let _approval = guardian_transfer_approval(&registry, &h, UNWRAP_SIG);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_unwrap_approval_transfer_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun guardian_transfer_approval_unwrap_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = guardian_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun guardian_bad_sig_transfer_fails() {
    let (registry, h) = guarded_harness();
    let _approval = guardian_transfer_approval(&registry, &h, BAD_SIG);
    abort
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun guardian_short_sig_transfer_fails() {
    let (registry, h) = guarded_harness();
    let _approval = guardian_transfer_approval(&registry, &h, x"bb");
    abort
}
