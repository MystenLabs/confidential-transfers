// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module payment_channel::payment_channel_tests;

use contra::{contra, policy::Auth, twisted_elgamal::PublicKey};
use payment_channel::payment_channel::{Self, Channel};
use std::unit_test::{Self, assert_eq};
use sui::{
    clock,
    coin::TreasuryCap,
    coin_registry::{Self, CoinRegistry, CurrencyInitializer},
    test_scenario::{Self, Scenario}
};

public struct TestCurrency has key { id: UID }

const SETUP_ADDR: address = @0x0;
const SENDER_ADDR: address = @0x100;
const RECEIVER_ADDR: address = @0x101;
const STRANGER_ADDR: address = @0x102;

// === new + accessors ===

#[test]
fun test_new_initial_state() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let env = setup_with_channel(&mut s, /* keypair seed */ 1);

    assert_eq!(env.channel.sender(), SENDER_ADDR);
    assert!(env.channel.state().is_initialized());
    assert!(env.channel.receiver().is_none());
    assert!(env.channel.end_time_ms().is_none());

    teardown(s, env);
}

// === get_auth gating ===

#[test]
fun test_get_auth_in_initialized_succeeds() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    let clk = clock::create_for_testing(s.ctx());
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();

    teardown(s, env);
}

#[test, expected_failure(abort_code = ::payment_channel::payment_channel::EUnauthorized)]
fun test_get_auth_wrong_sender_aborts() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    s.next_tx(STRANGER_ADDR);
    let clk = clock::create_for_testing(s.ctx());
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();

    teardown(s, env);
}

#[test, expected_failure(abort_code = ::payment_channel::payment_channel::EChannelActive)]
fun test_get_auth_active_no_sponsor_before_timeout_aborts() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, /* end */ 1_000, s.ctx());

    // No sponsor; clock < end_time_ms.
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(0);
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();

    teardown(s, env);
}

#[test, expected_failure(abort_code = ::payment_channel::payment_channel::EChannelActive)]
fun test_get_auth_active_wrong_sponsor_aborts() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());

    let next = s.ctx_builder().set_sponsor(STRANGER_ADDR);
    s.next_with_context(next);
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(0);
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();

    teardown(s, env);
}

#[test]
fun test_get_auth_active_with_receiver_sponsor_closes() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());
    assert!(env.channel.state().is_active());

    let next = s.ctx_builder().set_sponsor(RECEIVER_ADDR);
    s.next_with_context(next);
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(0);
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();

    assert!(env.channel.state().is_closed());
    teardown(s, env);
}

#[test]
fun test_get_auth_active_after_timeout_closes() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());
    assert!(env.channel.state().is_active());

    // No sponsor; clock past end_time_ms.
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(2_000);
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();

    assert!(env.channel.state().is_closed());
    teardown(s, env);
}

#[test]
fun test_get_auth_in_closed_succeeds() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    // Drive the channel to Closed via the timeout bypass.
    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(2_000);
    let auth1 = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth1);
    assert!(env.channel.state().is_closed());

    // Now in Closed: get_auth should succeed unconditionally.
    let auth2 = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth2);
    clk.destroy_for_testing();

    teardown(s, env);
}

// === activate gating ===

#[test]
fun test_activate_sets_active_state() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 12_345, s.ctx());

    assert!(env.channel.state().is_active());
    assert_eq!(env.channel.receiver(), option::some(RECEIVER_ADDR));
    assert_eq!(env.channel.end_time_ms(), option::some(12_345u64));

    teardown(s, env);
}

#[test, expected_failure(abort_code = ::payment_channel::payment_channel::EUnauthorized)]
fun test_activate_wrong_sender_aborts() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    s.next_tx(STRANGER_ADDR);
    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());

    teardown(s, env);
}

#[test, expected_failure(abort_code = ::payment_channel::payment_channel::ENotInitialized)]
fun test_activate_when_already_active_aborts() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());
    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());

    teardown(s, env);
}

#[test, expected_failure(abort_code = ::payment_channel::payment_channel::ENotInitialized)]
fun test_activate_when_closed_aborts() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(2_000);
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();
    assert!(env.channel.state().is_closed());

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());

    teardown(s, env);
}

// === State helpers ===

#[test]
fun test_state_helpers_are_disjoint() {
    let mut s = test_scenario::begin(SETUP_ADDR);
    let mut env = setup_with_channel(&mut s, 1);

    let st = env.channel.state();
    assert!(st.is_initialized());
    assert!(!st.is_active());
    assert!(!st.is_closed());

    payment_channel::activate(&mut env.channel, RECEIVER_ADDR, 1_000, s.ctx());
    let st = env.channel.state();
    assert!(!st.is_initialized());
    assert!(st.is_active());
    assert!(!st.is_closed());

    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(2_000);
    let auth = env_get_auth(&mut env, &clk, s.ctx());
    unit_test::destroy(auth);
    clk.destroy_for_testing();
    let st = env.channel.state();
    assert!(!st.is_initialized());
    assert!(!st.is_active());
    assert!(st.is_closed());

    teardown(s, env);
}

// === Helpers ===

/// Wrapper around `payment_channel::get_auth` that takes `&mut Env` instead
/// of separately borrowed `&mut env.channel` + `&env.ct`. The latter pattern
/// trips the Move borrow checker at the call site (it sees both args as
/// borrows of `env`); doing it through a helper hides the field-split inside
/// the function body where the checker is happy.
fun env_get_auth(env: &mut Env, clk: &clock::Clock, ctx: &TxContext): Auth<TestCurrency> {
    payment_channel::get_auth(&mut env.channel, &env.ct, clk, ctx)
}

public struct Env {
    ct: contra::ConfidentialToken<TestCurrency>,
    t_cap: TreasuryCap<TestCurrency>,
    builder: CurrencyInitializer<TestCurrency>,
    ct_registry: contra::TokenRegistry,
    coin_registry: CoinRegistry,
    management_cap: contra::ManagementCap<TestCurrency>,
    channel: Channel<TestCurrency>,
}

/// Common setup: create the contra token + a fresh `Channel<TestCurrency>`
/// under `SENDER_ADDR`. The channel's contra account is *not* created — these
/// tests only exercise the channel-level state machine + auth gating.
fun setup_with_channel(s: &mut Scenario, _keypair_seed: u64): Env {
    let mut ct_registry = contra::new_token_registry_for_testing(s.ctx());
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(s.ctx());
    let (builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        s.ctx(),
    );
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector<PublicKey>[],
        s.ctx(),
    );

    s.next_tx(SENDER_ADDR);
    payment_channel::new<TestCurrency>(s.ctx());

    s.next_tx(SENDER_ADDR);
    let channel: Channel<TestCurrency> = s.take_shared();

    Env {
        ct,
        t_cap,
        builder,
        ct_registry,
        coin_registry,
        management_cap,
        channel,
    }
}

fun teardown(s: Scenario, env: Env) {
    let Env {
        ct,
        t_cap,
        builder,
        ct_registry,
        coin_registry,
        management_cap,
        channel,
    } = env;
    test_scenario::return_shared(channel);
    unit_test::destroy(ct);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(management_cap);
    s.end();
}
