// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Integration tests for the canonical Nitro authority module and Contra protected operations.
#[test_only]
module contra::nitro_authority_integration_tests;

use contra::{
    authority::{Self, Approval},
    contra,
    custom_authority_for_testing,
    encrypted_amount::{
        Self,
        EncryptedAmount,
        consistency_proof_for_testing,
        sender_consistency_proof_for_testing,
    },
    nitro_authority,
    nizk,
    range_proof,
    twisted_elgamal::{Self, encrypt_trivial_for_testing, public_key}
};
use std::unit_test::{Self, assert_eq};
use sui::{coin_registry, deny_list, group_ops::Element, ristretto255::{Self, G}};

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
/// The Nitro authority operator.
const ALICE: address = @0xA11CE;

/// The fixture enclave key generated after the HPKE key from an all-zero RNG seed, and its
/// signatures over the `NitroAuthorityRequest` for the harness's 50-transfer and 40-unwrap.
const ENCLAVE_PK: vector<u8> = x"aef3f4a4b8eca1dfc343361bf8e436bd42de9259c04b8314eb8e2054dd6e82ab";
const ENC_PK: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRANSFER_SIG: vector<u8> =
    x"84e45a3610b67f47dcddcdbba86905c0334c021181423e832bc53780479309a77a9504cc85f250af1ba12d6434e107fc362281b899b685866fa64d5fc3d03f04";
const UNWRAP_SIG: vector<u8> =
    x"2c295c2b14645b081c7e9979215065c10d52165a09c99951e019daa563d2f17ae994ee7c3fde931263cc115c21329949eeedb7888e3aaa2f75144567a0af270f";
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

/// A harness whose token initially has `AuthorityKind::None` configured.
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

/// Create the `NitroAuthority<T>` derived from the harness's confidential token.
fun new_nitro_authority(h: &mut Harness): nitro_authority::NitroAuthority<TestCurrency> {
    nitro_authority::new(
        &mut h.ct,
        &h.management_cap,
        x"00",
        x"01",
        x"02",
        ALICE,
    )
}

/// Enable the canonical Nitro authority for the harness token.
fun enable_nitro_authority(h: &mut Harness) {
    contra::set_authority(
        &mut h.ct,
        &h.management_cap,
        authority::nitro_authority_kind_for_testing(),
    );
}

/// The issuer disables whichever authority is enabled for the harness token.
fun set_no_authority(h: &mut Harness) {
    contra::set_authority(
        &mut h.ct,
        &h.management_cap,
        authority::none(),
    );
}

/// A harness with a fixture NitroAuthority enabled as its authority.
fun guarded_harness(): (nitro_authority::NitroAuthority<TestCurrency>, Harness) {
    let mut h = new_harness();
    let mut nitro_authority = new_nitro_authority(&mut h);
    nitro_authority.register_enclave_for_testing(ENCLAVE_PK, ENC_PK);
    enable_nitro_authority(&mut h);
    (nitro_authority, h)
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
    contra::set_authority(
        &mut h.ct,
        &h.management_cap,
        authority::custom_authority_kind_for_testing(object::id(custom_authority)),
    );
}

// === Approval fixtures ===

/// The fixture's 50-transfer operation binding.
fun fixture_transfer_binding(h: &Harness): authority::Binding {
    authority::transfer_binding(
        h.account_1.token_public_key<TestCurrency>(),
        vector[public_key(pk_2())],
        h.account_1.balance_amount<TestCurrency>(),
        &amount_for_testing(50, &pk_1(), TRANSFER_BALANCE_R),
        &vector[amount_for_testing(50, &pk_2(), TRANSFER_R)],
    )
}

/// Digest of the fixture's 50-transfer operation binding.
fun transfer_digest(h: &Harness): vector<u8> {
    authority::digest_for_testing(&fixture_transfer_binding(h))
}

/// The fixture's 40-unwrap operation binding.
fun fixture_unwrap_binding(h: &Harness): authority::Binding {
    authority::unwrap_binding(
        h.account_1.token_public_key<TestCurrency>(),
        h.account_1.balance_amount<TestCurrency>(),
        &amount_for_testing(60, &pk_1(), UNWRAP_R),
        UNWRAP_AMOUNT,
    )
}

/// Digest of the fixture's 40-unwrap operation binding.
fun unwrap_digest(h: &Harness): vector<u8> {
    authority::digest_for_testing(&fixture_unwrap_binding(h))
}

fun nitro_authority_transfer_approval_at_key(
    nitro_authority: &nitro_authority::NitroAuthority<TestCurrency>,
    h: &Harness,
    key_index: u8,
    sig: vector<u8>,
): Option<Approval<TestCurrency>> {
    nitro_authority.new_approval<TestCurrency>(
        &h.ct,
        transfer_digest(h),
        key_index,
        sig,
    )
}

/// Nitro authority approval for the 50-transfer with the enclave signature `sig`.
fun nitro_authority_transfer_approval(
    nitro_authority: &nitro_authority::NitroAuthority<TestCurrency>,
    h: &Harness,
    sig: vector<u8>,
): Option<Approval<TestCurrency>> {
    nitro_authority_transfer_approval_at_key(nitro_authority, h, 0, sig)
}

/// Nitro authority approval for the 40-unwrap with the enclave signature `sig`.
fun nitro_authority_unwrap_approval(
    nitro_authority: &nitro_authority::NitroAuthority<TestCurrency>,
    h: &Harness,
    sig: vector<u8>,
): Option<Approval<TestCurrency>> {
    nitro_authority.new_approval<TestCurrency>(
        &h.ct,
        unwrap_digest(h),
        0,
        sig,
    )
}

// === Nitro authority lifecycle ===

#[test]
fun nitro_authority_can_be_created_enabled_and_shared_atomically() {
    let mut h = new_harness();
    let nitro_authority_obj = new_nitro_authority(&mut h);
    enable_nitro_authority(&mut h);
    nitro_authority::share(nitro_authority_obj);

    destroy(h);
}

#[test]
fun nitro_authority_can_be_enabled_after_sharing() {
    let mut h = new_harness();
    let nitro_authority_obj = new_nitro_authority(&mut h);
    nitro_authority::share(nitro_authority_obj);

    h.scenario.next_tx(SENDER);
    let nitro_authority_obj: nitro_authority::NitroAuthority<TestCurrency> = h
        .scenario
        .take_shared();
    let approval = nitro_authority_transfer_approval(&nitro_authority_obj, &h, BAD_SIG);
    assert!(approval.is_none());
    approval.destroy_none();
    enable_nitro_authority(&mut h);

    sui::test_scenario::return_shared(nitro_authority_obj);
    destroy(h);
}

#[test]
fun nitro_authority_rotation_scenarios() {
    let (mut nitro_authority_obj, mut h) = guarded_harness();
    // New pcrs, min_version unchanged.
    nitro_authority_obj.update(
        &h.management_cap,
        x"10",
        x"11",
        x"12",
        0,
        ALICE,
    );
    let new_key_index = nitro_authority_obj.register_enclave_for_testing(
        ENCLAVE_PK,
        ENC_PK,
    );
    assert_eq!(new_key_index, 1);
    assert!(nitro_authority_obj.contains_nitro_authority_enclave_key(0));

    let approval = nitro_authority_transfer_approval_at_key(
        &nitro_authority_obj,
        &h,
        0,
        TRANSFER_SIG,
    ).destroy_some();
    authority::verify_required_approval(option::some(approval), fixture_transfer_binding(&h));

    // Raise min_version.
    nitro_authority_obj.update(
        &h.management_cap,
        x"10",
        x"11",
        x"12",
        1,
        ALICE,
    );
    assert!(!nitro_authority_obj.contains_nitro_authority_enclave_key(0));

    let approval = nitro_authority_transfer_approval_at_key(
        &nitro_authority_obj,
        &h,
        new_key_index,
        TRANSFER_SIG,
    );
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(nitro_authority_obj);
}

#[test]
fun authority_lifecycle_scenarios() {
    let (nitro_authority_obj, mut h) = guarded_harness();
    enable_nitro_authority(&mut h);
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);

    let approval = custom_authority_for_testing::mint_approval(
        &custom_authority,
        &h.ct,
        &transfer_digest(&h),
    ).destroy_some();
    authority::verify_required_approval(option::some(approval), fixture_transfer_binding(&h));
    enable_nitro_authority(&mut h);
    let approval = nitro_authority_transfer_approval(
        &nitro_authority_obj,
        &h,
        TRANSFER_SIG,
    ).destroy_some();
    authority::verify_required_approval(option::some(approval), fixture_transfer_binding(&h));

    enable_custom_authority(&custom_authority, &mut h);
    set_no_authority(&mut h);
    set_no_authority(&mut h);
    let approval = custom_authority_for_testing::mint_approval(
        &custom_authority,
        &h.ct,
        &transfer_digest(&h),
    );
    assert!(approval.is_none());
    approval.destroy_none();
    enable_nitro_authority(&mut h);
    let approval = nitro_authority_transfer_approval(
        &nitro_authority_obj,
        &h,
        TRANSFER_SIG,
    ).destroy_some();
    authority::verify_required_approval(option::some(approval), fixture_transfer_binding(&h));
    enable_custom_authority(&custom_authority, &mut h);
    let approval = custom_authority_for_testing::mint_approval(
        &custom_authority,
        &h.ct,
        &unwrap_digest(&h),
    );
    execute_fixture_unwrap(&mut h, VALID_SK, approval);

    destroy(h);
    unit_test::destroy(nitro_authority_obj);
    unit_test::destroy(custom_authority);
}

#[test, expected_failure(abort_code = ::sui::derived_object::EObjectAlreadyExists)]
fun nitro_authority_can_only_be_created_once_per_confidential_token() {
    let mut h = new_harness();
    let _first = new_nitro_authority(&mut h);
    let _second = new_nitro_authority(&mut h);
    abort
}

#[test, expected_failure(abort_code = ::contra::nitro_authority::EEnclaveKeyNotRegistered)]
fun nitro_authority_rejects_unknown_enclave_key() {
    let mut h = new_harness();
    // Authority with no enclave keys registered.
    let nitro_authority_obj = new_nitro_authority(&mut h);
    enable_nitro_authority(&mut h);
    let _approval = nitro_authority_transfer_approval(&nitro_authority_obj, &h, TRANSFER_SIG);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EWrongAuthority)]
fun replaced_custom_authority_cannot_mint_approval() {
    let mut h = new_harness();
    let custom_authority_a = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority_a, &mut h);
    let custom_authority_b = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority_b, &mut h);
    let _approval = custom_authority_for_testing::mint_approval(
        &custom_authority_a,
        &h.ct,
        &transfer_digest(&h),
    );
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EWrongAuthority)]
fun replaced_nitro_authority_cannot_mint_approval() {
    let (nitro_authority_obj, mut h) = guarded_harness();
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    let _approval = nitro_authority_transfer_approval(&nitro_authority_obj, &h, TRANSFER_SIG);
    abort
}

// === Protected operation approval matrix ===
//
// TODO: extend this matrix when more protected operations are added.
// `disabled` means the token has `AuthorityKind::None` configured.
//
// | authority state | approval                                    | balance proof | result                     |
// |-----------------|---------------------------------------------|---------------|----------------------------|
// | disabled        | none                                        | valid         | pass                       |
// | disabled        | approval minted before disabling            | valid         | pass (approval discarded)  |
// | disabled        | invalid Nitro signature (no-op)             | valid         | pass                       |
// | enabled         | Nitro authority, valid signature            | valid         | pass                       |
// | enabled         | custom authority, valid approval            | valid         | pass                       |
// | disabled        | none                                        | invalid       | EBalanceProofFailed        |
// | enabled         | Nitro authority, valid signature            | invalid       | EBalanceProofFailed        |
// | enabled         | none                                        | valid         | EApprovalRequired          |
// | enabled         | as above, but the balance moves before use  | valid         | EApprovalMismatch          |
// | enabled         | valid approval, operation arguments changed | valid         | EApprovalMismatch          |
// | enabled         | Nitro approval for the other operation      | valid         | EApprovalMismatch          |
// | enabled         | signature over the other operation          | valid         | EApprovalSignatureMismatch |
// | enabled         | bad Nitro signature                         | not reached   | EApprovalSignatureMismatch |

#[test]
fun disabled_authority_no_approval_transfer_passes() {
    let (registry, mut h) = guarded_harness();
    set_no_authority(&mut h);
    execute_fixture_transfer(&mut h, VALID_SK, option::none());
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun disabled_authority_existing_approval_transfer_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
    set_no_authority(&mut h);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun disabled_authority_existing_approval_unwrap_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_unwrap_approval(&registry, &h, UNWRAP_SIG);
    set_no_authority(&mut h);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun disabled_nitro_authority_bad_sig_transfer_passes() {
    let (registry, mut h) = guarded_harness();
    set_no_authority(&mut h);
    let approval = nitro_authority_transfer_approval(&registry, &h, BAD_SIG);
    assert!(approval.is_none());
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun disabled_nitro_authority_bad_sig_unwrap_passes() {
    let (registry, mut h) = guarded_harness();
    set_no_authority(&mut h);
    let approval = nitro_authority_unwrap_approval(&registry, &h, BAD_SIG);
    assert!(approval.is_none());
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

// --- Nitro authority ---

#[test]
fun nitro_authority_valid_sig_transfer_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun nitro_authority_valid_sig_unwrap_passes() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(registry);
}

#[test]
fun custom_authority_valid_approval_transfer_passes() {
    let mut h = new_harness();
    let custom_authority = new_custom_authority(&mut h);
    enable_custom_authority(&custom_authority, &mut h);
    let approval = custom_authority_for_testing::mint_approval(
        &custom_authority,
        &h.ct,
        &transfer_digest(&h),
    );
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    destroy(h);
    unit_test::destroy(custom_authority);
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun disabled_authority_invalid_proof_transfer_fails() {
    let mut h = new_harness();
    execute_fixture_transfer(&mut h, INVALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun disabled_authority_invalid_proof_unwrap_fails() {
    let mut h = new_harness();
    execute_fixture_unwrap(&mut h, INVALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun nitro_authority_valid_sig_invalid_proof_transfer_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_fixture_transfer(&mut h, INVALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun nitro_authority_valid_sig_invalid_proof_unwrap_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_fixture_unwrap(&mut h, INVALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalRequired)]
fun nitro_authority_missing_approval_transfer_fails() {
    let (_registry, mut h) = guarded_harness();
    execute_fixture_transfer(&mut h, VALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalRequired)]
fun nitro_authority_missing_approval_unwrap_fails() {
    let (_registry, mut h) = guarded_harness();
    execute_fixture_unwrap(&mut h, VALID_SK, option::none());
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun nitro_authority_stale_approval_transfer_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
    bump_balance(&mut h);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun nitro_authority_stale_approval_unwrap_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_unwrap_approval(&registry, &h, UNWRAP_SIG);
    bump_balance(&mut h);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun nitro_authority_changed_transfer_receiver_key_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
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
fun nitro_authority_changed_transfer_receiver_encryption_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
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
fun nitro_authority_changed_transfer_new_balance_encryption_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
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
fun nitro_authority_changed_unwrap_amount_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_unwrap_with_inputs(&mut h, VALID_SK, 59, UNWRAP_R, UNWRAP_AMOUNT + 1, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun nitro_authority_changed_unwrap_new_balance_encryption_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_unwrap_approval(&registry, &h, UNWRAP_SIG);
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

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun nitro_authority_unwrap_approval_transfer_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_unwrap_approval(&registry, &h, UNWRAP_SIG);
    execute_fixture_transfer(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::authority::EApprovalMismatch)]
fun nitro_authority_transfer_approval_unwrap_fails() {
    let (registry, mut h) = guarded_harness();
    let approval = nitro_authority_transfer_approval(&registry, &h, TRANSFER_SIG);
    execute_fixture_unwrap(&mut h, VALID_SK, approval);
    abort
}

#[test, expected_failure(abort_code = ::contra::nitro_authority::EApprovalSignatureMismatch)]
fun nitro_authority_unwrap_sig_transfer_fails() {
    let (registry, h) = guarded_harness();
    let _approval = nitro_authority_transfer_approval(&registry, &h, UNWRAP_SIG);
    abort
}

#[test, expected_failure(abort_code = ::contra::nitro_authority::EApprovalSignatureMismatch)]
fun nitro_authority_bad_sig_transfer_fails() {
    let (registry, h) = guarded_harness();
    let _approval = nitro_authority_transfer_approval(&registry, &h, BAD_SIG);
    abort
}
