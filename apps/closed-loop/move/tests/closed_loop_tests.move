// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module closed_loop::closed_loop_tests;

use bu_token::bu::{Self, BuTreasury};
use closed_loop::{confidential_pbu::{Self, Whitelist}, pbu::{Self, PBU, Pool as PbuPool}};
use contra::{
    contra::{Self, ConfidentialToken, Pool as ContraPool, protocol_id_ddh, protocol_id_elgamal},
    encrypted_amount::{Self, collapse_for_testing, consistency_proof_for_testing},
    nizk,
    twisted_elgamal::{Self, encrypt_trivial_for_testing, encrypt_zero_for_testing}
};
use std::unit_test::{Self, assert_eq};
use sui::{deny_list, ristretto255, test_scenario};

/// Full closed-loop flow:
///   mint BU -> swap BU->pBU -> wrap pBU -> confidential transfer -> unwrap pBU -> swap pBU->BU.
#[test]
fun closed_loop_roundtrip() {
    let setup_addr = @0x0;
    let alice = @0x100;
    let bob = @0x101;

    let sk_alice = ristretto255::scalar_from_u64(12345);
    let pk_alice = ristretto255::g_mul(&sk_alice, &ristretto255::g_generator());
    let sk_bob = ristretto255::scalar_from_u64(67890);
    let pk_bob = ristretto255::g_mul(&sk_bob, &ristretto255::g_generator());

    let mut scenario = test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());
    bu::init_for_testing(scenario.ctx());
    let pbu_admin_cap = pbu::init_for_testing(scenario.ctx());

    scenario.next_tx(setup_addr);
    let deny_list: deny_list::DenyList = scenario.take_shared();
    let mut bu_treasury: BuTreasury = scenario.take_shared();
    let mut pbu_pool: PbuPool = scenario.take_shared();
    let mut token_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut account_registry = contra::new_account_registry_for_testing(scenario.ctx());

    let (management_cap, whitelist_cap) = confidential_pbu::setup(
        &pbu_admin_cap,
        &mut pbu_pool,
        &mut token_registry,
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);
    let ct: ConfidentialToken<PBU> = scenario.take_shared();
    let mut whitelist: Whitelist = scenario.take_shared();
    let mut contra_pool: ContraPool<PBU> = scenario.take_shared();

    confidential_pbu::add_to_whitelist(&whitelist_cap, &mut whitelist, alice);
    confidential_pbu::add_to_whitelist(&whitelist_cap, &mut whitelist, bob);

    scenario.next_tx(alice);
    let mut alice_account = account_registry.new(alice);
    confidential_pbu::register(&ct, &whitelist, &mut alice_account, pk_alice, scenario.ctx());

    scenario.next_tx(bob);
    let mut bob_account = account_registry.new(bob);
    confidential_pbu::register(&ct, &whitelist, &mut bob_account, pk_bob, scenario.ctx());

    // Alice: mint BU, swap to pBU, wrap into her confidential balance.
    scenario.next_tx(alice);
    let bu_coin = bu::mint(&mut bu_treasury, 100, scenario.ctx());
    assert_eq!(bu_coin.value(), 100);
    let pbu_coin = pbu::bu_to_pbu(&mut pbu_pool, bu_coin, scenario.ctx());
    assert_eq!(pbu_coin.value(), 100);

    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::wrap(
        &mut alice_account,
        &auth,
        &ct,
        &deny_list,
        &contra_pool,
        pbu_coin,
        vector[],
    );
    alice_account.merge<PBU>(&auth);

    // Alice: confidential transfer of 50 pBU to Bob.
    scenario.next_tx(alice);
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_alice, 10097),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
    );
    let r = 32533; // randomness shared between sender- and receiver-side encryptions
    let taken_amount = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_bob, r),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
    );
    // The collapsed sender total (value 50, blinding r) under pk_alice. The chain reconstructs its
    // commitment from the receiver amounts; only the single decryption handle is sent.
    let total_sender_enc = encrypt_trivial_for_testing(50, &pk_alice, r);
    let total_sender_handle = total_sender_enc.decryption_handle_for_testing();
    // Single consistency proof on the collapsed sender total (value 50, blinding r) under pk_alice.
    let consistency_proof = encrypted_amount::total_consistency_proof_for_testing(
        alice_account.derive_dst_for_testing<PBU>(protocol_id_elgamal()),
        50,
        r,
        &pk_alice,
    );
    let new_balance_encryption = new_balance.collapse_for_testing();
    let alice_old_balance = alice_account.balance<PBU>();
    let sum_proof = nizk::sum_proof_for_testing(
        alice_account.derive_dst_for_testing<PBU>(protocol_id_ddh()),
        &alice_old_balance,
        &new_balance_encryption,
        &total_sender_enc,
        &sk_alice,
    );

    let alice_elgamal_dst = alice_account.derive_dst_for_testing<PBU>(protocol_id_elgamal());
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(alice_elgamal_dst, 50, &taken_amount, r, &pk_bob),
        consistency_proof_for_testing(alice_elgamal_dst, 50, &new_balance, 10097, &pk_alice),
    ]);

    let auth = ct.authorize_as_sender(scenario.ctx());
    alice_account
        .batched_transfer<PBU>(
            &auth,
            &ct,
            &deny_list,
            vector[pk_bob],
            vector[taken_amount],
            well_formed_proofs,
            total_sender_handle,
            consistency_proof,
            ristretto255::g_identity(),
            new_balance,
            sum_proof,
        )
        .add<PBU>(&mut bob_account, vector[], &deny_list)
        .finalize();

    // Bob: merge deposits, unwrap 50 pBU back to a public coin.
    scenario.next_tx(bob);
    let auth = ct.authorize_as_sender(scenario.ctx());
    bob_account.merge<PBU>(&auth);

    let new_bob_balance = encrypted_amount::new_encrypted_amount(
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
        encrypt_zero_for_testing(),
    );
    // Prove: new_bob_balance + trivial(50) == bob_account.balance<PBU>()
    let unwrap_amount_trivial = encrypt_trivial_for_testing(50, &pk_bob, 0);
    let bob_new_balance_encryption = new_bob_balance.collapse_for_testing();
    let bob_old_balance = bob_account.balance<PBU>();
    let bob_balance_proof = nizk::sum_proof_for_testing(
        bob_account.derive_dst_for_testing<PBU>(protocol_id_ddh()),
        &bob_old_balance,
        &bob_new_balance_encryption,
        &unwrap_amount_trivial,
        &sk_bob,
    );
    let new_bob_balance_proof = encrypted_amount::new_well_formed_proof_singleton_for_testing(
        consistency_proof_for_testing(
            bob_account.derive_dst_for_testing<PBU>(protocol_id_elgamal()),
            0,
            &new_bob_balance,
            0,
            &pk_bob,
        ),
    );
    let pbu_coin_out = bob_account.unwrap(
        &auth,
        &ct,
        &deny_list,
        &mut contra_pool,
        new_bob_balance,
        new_bob_balance_proof,
        50,
        &bob_balance_proof,
        scenario.ctx(),
    );
    assert_eq!(pbu_coin_out.value(), 50);

    // Bob: pBU -> BU, closing the loop.
    let bu_coin_out = pbu::pbu_to_bu(&mut pbu_pool, pbu_coin_out, scenario.ctx());
    assert_eq!(bu_coin_out.value(), 50);

    // teardown
    unit_test::destroy(bu_coin_out);
    unit_test::destroy(alice_account);
    unit_test::destroy(bob_account);
    unit_test::destroy(account_registry);
    unit_test::destroy(token_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(whitelist_cap);
    unit_test::destroy(pbu_admin_cap);
    test_scenario::return_shared(ct);
    test_scenario::return_shared(whitelist);
    test_scenario::return_shared(contra_pool);
    test_scenario::return_shared(bu_treasury);
    test_scenario::return_shared(pbu_pool);
    test_scenario::return_shared(deny_list);
    scenario.end();
}

/// Non-whitelisted senders must not be able to call `register`.
#[test, expected_failure(abort_code = confidential_pbu::ENotWhitelisted)]
fun register_requires_whitelist() {
    let setup_addr = @0x0;
    let mallory = @0x200;

    let sk = ristretto255::scalar_from_u64(42);
    let pk = ristretto255::g_mul(&sk, &ristretto255::g_generator());

    let mut scenario = test_scenario::begin(setup_addr);
    let pbu_admin_cap = pbu::init_for_testing(scenario.ctx());

    scenario.next_tx(setup_addr);
    let mut pbu_pool: PbuPool = scenario.take_shared();
    let mut token_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut account_registry = contra::new_account_registry_for_testing(scenario.ctx());

    let (management_cap, whitelist_cap) = confidential_pbu::setup(
        &pbu_admin_cap,
        &mut pbu_pool,
        &mut token_registry,
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);
    let ct: ConfidentialToken<PBU> = scenario.take_shared();
    let whitelist: Whitelist = scenario.take_shared();
    let contra_pool: ContraPool<PBU> = scenario.take_shared();

    // `mallory` is not on the whitelist -> this aborts.
    scenario.next_tx(mallory);
    let mut mallory_account = account_registry.new(mallory);
    confidential_pbu::register(&ct, &whitelist, &mut mallory_account, pk, scenario.ctx());

    unit_test::destroy(mallory_account);
    unit_test::destroy(account_registry);
    unit_test::destroy(token_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(whitelist_cap);
    unit_test::destroy(pbu_admin_cap);
    test_scenario::return_shared(ct);
    test_scenario::return_shared(whitelist);
    test_scenario::return_shared(contra_pool);
    test_scenario::return_shared(pbu_pool);
    scenario.end();
}

/// Non-whitelisted senders must not be able to call `set_public_key`.
#[test, expected_failure(abort_code = confidential_pbu::ENotWhitelisted)]
fun set_public_key_requires_whitelist() {
    let setup_addr = @0x0;
    let alice = @0x100;
    let mallory = @0x200;

    let sk = ristretto255::scalar_from_u64(42);
    let pk = ristretto255::g_mul(&sk, &ristretto255::g_generator());
    let new_pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(43),
        &ristretto255::g_generator(),
    );

    let mut scenario = test_scenario::begin(setup_addr);
    let pbu_admin_cap = pbu::init_for_testing(scenario.ctx());

    scenario.next_tx(setup_addr);
    let mut pbu_pool: PbuPool = scenario.take_shared();
    let mut token_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut account_registry = contra::new_account_registry_for_testing(scenario.ctx());

    let (management_cap, whitelist_cap) = confidential_pbu::setup(
        &pbu_admin_cap,
        &mut pbu_pool,
        &mut token_registry,
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);
    let ct: ConfidentialToken<PBU> = scenario.take_shared();
    let mut whitelist: Whitelist = scenario.take_shared();
    let contra_pool: ContraPool<PBU> = scenario.take_shared();

    // Whitelist alice so she can register, but mallory remains off the list.
    confidential_pbu::add_to_whitelist(&whitelist_cap, &mut whitelist, alice);

    scenario.next_tx(alice);
    let mut alice_account = account_registry.new(alice);
    confidential_pbu::register(&ct, &whitelist, &mut alice_account, pk, scenario.ctx());

    // Dummy re-key args so the call type-checks; the whitelist abort fires before any proof
    // verification.
    let new_handles = vector[new_pk, new_pk, new_pk, new_pk];

    // `mallory` is not on the whitelist -> this aborts.
    scenario.next_tx(mallory);
    confidential_pbu::set_public_key(
        &ct,
        &whitelist,
        &mut alice_account,
        new_pk,
        new_handles,
        nizk::default_batched_ddh_proof(),
        scenario.ctx(),
    );

    unit_test::destroy(alice_account);
    unit_test::destroy(account_registry);
    unit_test::destroy(token_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(whitelist_cap);
    unit_test::destroy(pbu_admin_cap);
    test_scenario::return_shared(ct);
    test_scenario::return_shared(whitelist);
    test_scenario::return_shared(contra_pool);
    test_scenario::return_shared(pbu_pool);
    scenario.end();
}
