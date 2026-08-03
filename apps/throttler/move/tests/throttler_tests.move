// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module throttler::throttler_tests;

use contra::{
    contra::{Self, ConfidentialToken, Pool as ContraPool, protocol_id_ddh, protocol_id_elgamal},
    encrypted_amount::{Self, consistency_proof_for_testing},
    nizk,
    twisted_elgamal::{Self, encrypt_trivial_for_testing, encrypt_zero_for_testing}
};
use std::unit_test::{Self, assert_eq};
use sui::{clock, coin, deny_list, ristretto255, test_scenario};
use throttler::{bu::{Self, BU}, confidential_bu::{Self, ThrottledPool}};

/// Mint `amount` BU into Alice's confidential balance. Encapsulates the
/// scenario-state plumbing shared by the tests below; assumes Alice has
/// already registered a confidential `TokenAccount` and `scenario`'s next
/// tx will be Alice's.
fun wrap_for_alice(
    treasury_cap: &mut coin::TreasuryCap<BU>,
    alice_account: &mut contra::Account,
    ct: &ConfidentialToken<BU>,
    deny_list: &deny_list::DenyList,
    contra_pool: &ContraPool<BU>,
    amount: u64,
    scenario: &mut test_scenario::Scenario,
) {
    let bu_coin = coin::mint(treasury_cap, amount, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::wrap(
        alice_account,
        &auth,
        ct,
        deny_list,
        contra_pool,
        bu_coin,
        vector[],
    );
    alice_account.merge<BU>(&auth);
}

/// Build the proofs and call `confidential_bu::unwrap`, leaving an
/// `amount`-valued claim on Alice's queue with `request_time` equal to the
/// current `clock.timestamp_ms()`. `new_balance_value` is the value Alice
/// will hold in limb 0 after the unwrap (the test caller chooses this so
/// the homomorphic balance check passes).
fun do_throttled_unwrap(
    ct: &ConfidentialToken<BU>,
    alice_account: &mut contra::Account,
    deny_list: &deny_list::DenyList,
    contra_pool: &mut ContraPool<BU>,
    throttled_pool: &mut ThrottledPool,
    sk_alice: &sui::group_ops::Element<sui::ristretto255::Scalar>,
    pk_alice: &sui::group_ops::Element<sui::ristretto255::G>,
    amount: u64,
    new_balance_value: u64,
    clock: &clock::Clock,
    scenario: &mut test_scenario::Scenario,
) {
    let blinding: u64 = 11111;
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(new_balance_value, pk_alice, blinding),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
    );
    let unwrap_amount_trivial = encrypt_trivial_for_testing(amount, pk_alice, 0);
    let new_balance_encryption = new_balance.collapse_for_testing();
    let old_balance = alice_account.balance<BU>();
    let balance_proof = nizk::sum_proof_for_testing(
        alice_account.derive_dst_for_testing<BU>(protocol_id_ddh()),
        &old_balance,
        &new_balance_encryption,
        &unwrap_amount_trivial,
        sk_alice,
    );
    let elgamal_sid = alice_account.derive_dst_for_testing<BU>(protocol_id_elgamal());
    let new_balance_proof = encrypted_amount::new_well_formed_proof_singleton_for_testing(
        consistency_proof_for_testing(
            elgamal_sid,
            new_balance_value as u16,
            &new_balance,
            blinding,
            pk_alice,
        ),
    );
    confidential_bu::unwrap(
        ct,
        alice_account,
        deny_list,
        contra_pool,
        throttled_pool,
        new_balance,
        new_balance_proof,
        amount,
        &balance_proof,
        clock,
        scenario.ctx(),
    );
}

/// Full happy-path roundtrip: wrap 100 BU, throttle-unwrap 50, verify that
/// `take` returns 0 before the entry matures, advance the clock past
/// `min_duration`, then verify `take` returns the full 50 BU.
#[test]
fun throttled_unwrap_roundtrip() {
    let setup_addr = @0x0;
    let alice = @0x100;

    let sk_alice = ristretto255::scalar_from_u64(12345);
    let pk_alice = ristretto255::g_mul(&sk_alice, &ristretto255::g_generator());

    let mut scenario = test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());

    let (mut treasury_cap, admin_cap) = bu::init_for_testing(scenario.ctx());

    scenario.next_tx(setup_addr);
    let deny_list: deny_list::DenyList = scenario.take_shared();
    let mut token_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut account_registry = contra::new_account_registry_for_testing(scenario.ctx());

    let min_duration: u64 = 60_000;
    let management_cap = confidential_bu::setup(
        &mut treasury_cap,
        &mut token_registry,
        min_duration,
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);
    let ct: ConfidentialToken<BU> = scenario.take_shared();
    let mut throttled_pool: ThrottledPool = scenario.take_shared();
    let mut contra_pool: ContraPool<BU> = scenario.take_shared();

    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(1_000);

    scenario.next_tx(alice);
    let mut alice_account = account_registry.new(alice, pk_alice);
    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::register(&mut alice_account, &auth);

    wrap_for_alice(
        &mut treasury_cap,
        &mut alice_account,
        &ct,
        &deny_list,
        &contra_pool,
        100,
        &mut scenario,
    );

    do_throttled_unwrap(
        &ct,
        &mut alice_account,
        &deny_list,
        &mut contra_pool,
        &mut throttled_pool,
        &sk_alice,
        &pk_alice,
        50,
        50,
        &clock,
        &mut scenario,
    );

    // take before min_duration: nothing matures, return zero coin.
    let early = confidential_bu::take(&mut throttled_pool, &clock, scenario.ctx());
    assert_eq!(early.value(), 0);
    early.destroy_zero();

    // Advance to the maturation boundary and claim.
    clock.increment_for_testing(min_duration);
    let matured = confidential_bu::take(&mut throttled_pool, &clock, scenario.ctx());
    assert_eq!(matured.value(), 50);

    // A second take returns zero — the dynamic field was deleted.
    let nothing_left = confidential_bu::take(&mut throttled_pool, &clock, scenario.ctx());
    assert_eq!(nothing_left.value(), 0);
    nothing_left.destroy_zero();

    unit_test::destroy(matured);
    unit_test::destroy(treasury_cap);
    unit_test::destroy(admin_cap);
    unit_test::destroy(management_cap);
    unit_test::destroy(alice_account);
    unit_test::destroy(account_registry);
    unit_test::destroy(token_registry);
    clock.destroy_for_testing();
    test_scenario::return_shared(ct);
    test_scenario::return_shared(throttled_pool);
    test_scenario::return_shared(contra_pool);
    test_scenario::return_shared(deny_list);
    scenario.end();
}

/// `unwrap` must abort when `ctx.sender()` is not `account.owner`.
#[test, expected_failure(abort_code = confidential_bu::EUnauthorized)]
fun unwrap_aborts_for_non_owner() {
    let setup_addr = @0x0;
    let alice = @0x100;
    let mallory = @0x200;

    let sk_alice = ristretto255::scalar_from_u64(12345);
    let pk_alice = ristretto255::g_mul(&sk_alice, &ristretto255::g_generator());

    let mut scenario = test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());

    let (mut treasury_cap, admin_cap) = bu::init_for_testing(scenario.ctx());

    scenario.next_tx(setup_addr);
    let deny_list: deny_list::DenyList = scenario.take_shared();
    let mut token_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut account_registry = contra::new_account_registry_for_testing(scenario.ctx());

    let management_cap = confidential_bu::setup(
        &mut treasury_cap,
        &mut token_registry,
        60_000,
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);
    let ct: ConfidentialToken<BU> = scenario.take_shared();
    let mut throttled_pool: ThrottledPool = scenario.take_shared();
    let mut contra_pool: ContraPool<BU> = scenario.take_shared();

    let clock = clock::create_for_testing(scenario.ctx());

    scenario.next_tx(alice);
    let mut alice_account = account_registry.new(alice, pk_alice);
    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::register(&mut alice_account, &auth);

    wrap_for_alice(
        &mut treasury_cap,
        &mut alice_account,
        &ct,
        &deny_list,
        &contra_pool,
        100,
        &mut scenario,
    );

    // Mallory tries to unwrap from Alice's account.
    scenario.next_tx(mallory);
    do_throttled_unwrap(
        &ct,
        &mut alice_account,
        &deny_list,
        &mut contra_pool,
        &mut throttled_pool,
        &sk_alice,
        &pk_alice,
        50,
        50,
        &clock,
        &mut scenario,
    );

    unit_test::destroy(treasury_cap);
    unit_test::destroy(admin_cap);
    unit_test::destroy(management_cap);
    unit_test::destroy(alice_account);
    unit_test::destroy(account_registry);
    unit_test::destroy(token_registry);
    clock.destroy_for_testing();
    test_scenario::return_shared(ct);
    test_scenario::return_shared(throttled_pool);
    test_scenario::return_shared(contra_pool);
    test_scenario::return_shared(deny_list);
    scenario.end();
}

/// Issuer seize path: clear Alice's queue, reassign her claim to the
/// issuer's address with `request_time: 0`, then claim via `take`.
#[test]
fun issuer_can_seize_via_set_pending() {
    let setup_addr = @0x0;
    let alice = @0x100;
    let issuer = @0x999;

    let sk_alice = ristretto255::scalar_from_u64(12345);
    let pk_alice = ristretto255::g_mul(&sk_alice, &ristretto255::g_generator());

    let mut scenario = test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());

    let (mut treasury_cap, admin_cap) = bu::init_for_testing(scenario.ctx());

    scenario.next_tx(setup_addr);
    let deny_list: deny_list::DenyList = scenario.take_shared();
    let mut token_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut account_registry = contra::new_account_registry_for_testing(scenario.ctx());

    let min_duration: u64 = 60_000;
    let management_cap = confidential_bu::setup(
        &mut treasury_cap,
        &mut token_registry,
        min_duration,
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);
    let ct: ConfidentialToken<BU> = scenario.take_shared();
    let mut throttled_pool: ThrottledPool = scenario.take_shared();
    let mut contra_pool: ContraPool<BU> = scenario.take_shared();

    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(1_000);

    scenario.next_tx(alice);
    let mut alice_account = account_registry.new(alice, pk_alice);
    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::register(&mut alice_account, &auth);

    wrap_for_alice(
        &mut treasury_cap,
        &mut alice_account,
        &ct,
        &deny_list,
        &contra_pool,
        100,
        &mut scenario,
    );

    do_throttled_unwrap(
        &ct,
        &mut alice_account,
        &deny_list,
        &mut contra_pool,
        &mut throttled_pool,
        &sk_alice,
        &pk_alice,
        50,
        50,
        &clock,
        &mut scenario,
    );

    // Issuer seizes: clear Alice's pending queue and reassign 50 BU to
    // their own address with request_time 0 (already matured).
    scenario.next_tx(issuer);
    confidential_bu::set_pending(&admin_cap, &mut throttled_pool, alice, vector[]);
    confidential_bu::set_pending(
        &admin_cap,
        &mut throttled_pool,
        issuer,
        vector[confidential_bu::new_pending(50, 0)],
    );

    // Need to advance past min_duration since the entry's request_time is 0.
    clock.increment_for_testing(min_duration);
    let issuer_coin = confidential_bu::take(&mut throttled_pool, &clock, scenario.ctx());
    assert_eq!(issuer_coin.value(), 50);

    // Alice's queue is empty -> take returns zero.
    scenario.next_tx(alice);
    let alice_coin = confidential_bu::take(&mut throttled_pool, &clock, scenario.ctx());
    assert_eq!(alice_coin.value(), 0);
    alice_coin.destroy_zero();

    unit_test::destroy(issuer_coin);
    unit_test::destroy(treasury_cap);
    unit_test::destroy(admin_cap);
    unit_test::destroy(management_cap);
    unit_test::destroy(alice_account);
    unit_test::destroy(account_registry);
    unit_test::destroy(token_registry);
    clock.destroy_for_testing();
    test_scenario::return_shared(ct);
    test_scenario::return_shared(throttled_pool);
    test_scenario::return_shared(contra_pool);
    test_scenario::return_shared(deny_list);
    scenario.end();
}

/// `set_min_duration` retroactively shortens the maturation window.
#[test]
fun set_min_duration_shortens_window() {
    let setup_addr = @0x0;
    let alice = @0x100;

    let sk_alice = ristretto255::scalar_from_u64(12345);
    let pk_alice = ristretto255::g_mul(&sk_alice, &ristretto255::g_generator());

    let mut scenario = test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());

    let (mut treasury_cap, admin_cap) = bu::init_for_testing(scenario.ctx());

    scenario.next_tx(setup_addr);
    let deny_list: deny_list::DenyList = scenario.take_shared();
    let mut token_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut account_registry = contra::new_account_registry_for_testing(scenario.ctx());

    let initial_duration: u64 = 1_000_000;
    let management_cap = confidential_bu::setup(
        &mut treasury_cap,
        &mut token_registry,
        initial_duration,
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);
    let ct: ConfidentialToken<BU> = scenario.take_shared();
    let mut throttled_pool: ThrottledPool = scenario.take_shared();
    let mut contra_pool: ContraPool<BU> = scenario.take_shared();

    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(1_000);

    scenario.next_tx(alice);
    let mut alice_account = account_registry.new(alice, pk_alice);
    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::register(&mut alice_account, &auth);

    wrap_for_alice(
        &mut treasury_cap,
        &mut alice_account,
        &ct,
        &deny_list,
        &contra_pool,
        100,
        &mut scenario,
    );

    do_throttled_unwrap(
        &ct,
        &mut alice_account,
        &deny_list,
        &mut contra_pool,
        &mut throttled_pool,
        &sk_alice,
        &pk_alice,
        50,
        50,
        &clock,
        &mut scenario,
    );

    // 10s later the original 1000s window has not elapsed.
    clock.increment_for_testing(10_000);
    let early = confidential_bu::take(&mut throttled_pool, &clock, scenario.ctx());
    assert_eq!(early.value(), 0);
    early.destroy_zero();

    // Issuer cuts the window to 5s; the existing entry retroactively matures.
    confidential_bu::set_min_duration(&admin_cap, &mut throttled_pool, 5_000);
    let matured = confidential_bu::take(&mut throttled_pool, &clock, scenario.ctx());
    assert_eq!(matured.value(), 50);

    unit_test::destroy(matured);
    unit_test::destroy(treasury_cap);
    unit_test::destroy(admin_cap);
    unit_test::destroy(management_cap);
    unit_test::destroy(alice_account);
    unit_test::destroy(account_registry);
    unit_test::destroy(token_registry);
    clock.destroy_for_testing();
    test_scenario::return_shared(ct);
    test_scenario::return_shared(throttled_pool);
    test_scenario::return_shared(contra_pool);
    test_scenario::return_shared(deny_list);
    scenario.end();
}
