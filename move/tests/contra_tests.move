// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module contra::contra_tests;

use contra::{
    auditors,
    balance::EncryptedCoin,
    contra,
    encrypted_amount::{Self, consistency_proof_for_testing},
    nizk,
    policy,
    range_proof,
    session_id,
    twisted_elgamal::{encrypt_trivial_for_testing, encrypt_zero, public_key, PublicKey, Encryption}
};
use std::unit_test::{Self, assert_eq};
use sui::{
    coin::deny_list_v2_add,
    coin_registry,
    deny_list,
    group_ops::Element,
    ristretto255::{Self, G},
    test_scenario::ctx
};

/// Type for Currency creation.
public struct TestCurrency has key { id: UID }

public struct Witness has drop {}

#[test]
fun create_account() {
    let pk = ristretto255::g_mul(&ristretto255::scalar_from_u64(7), &ristretto255::g_generator());
    let ctx = &mut tx_context::dummy();
    let owner = ctx.sender();
    let mut acc_reg = contra::new_account_registry_for_testing(ctx);
    let account = acc_reg.new(ctx.sender());

    assert_eq!(account.owner(), owner);

    unit_test::destroy(account);
    unit_test::destroy(acc_reg);
}

#[test]
fun create_confidential_token() {
    let setup_addr = @0x0;
    let mut scenario = sui::test_scenario::begin(setup_addr);
    let ctx = &mut tx_context::dummy();
    let mut ct_registry = contra::new_token_registry_for_testing(ctx);
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(ctx);
    let (builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(8, "_", "_", "_", "_", ctx);

    // Confidential token object (auditing disabled).
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    scenario.next_tx(setup_addr);

    unit_test::destroy(ct);
    unit_test::destroy(management_cap);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    scenario.end();
}

#[test]
fun test_simple_flow() {
    let setup_addr = @0x0;

    // Setup addresses
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());

    let addr2 = @0x101;
    let sk_2 = ristretto255::scalar_from_u64(67890);
    let pk_2 = ristretto255::g_mul(&sk_2, &ristretto255::g_generator());

    // Account 1 sets up a new currency and creates a confidential token for it. Account 1 also registers itself in the account registry and adds the currency to its account.
    let mut scenario = sui::test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());
    scenario.next_tx(setup_addr);
    let deny_list: deny_list::DenyList = scenario.take_shared();

    let mut acc_reg = contra::new_account_registry_for_testing(scenario.ctx());
    let mut ct_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(scenario.ctx());
    let (mut builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        scenario.ctx(),
    );
    let _deny_cap = builder.make_regulated(true, scenario.ctx());

    scenario.next_tx(addr1);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    ct.set_policy<TestCurrency, Witness>(&mut t_cap, vector[0u8]);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_with_witness<TestCurrency, Witness>(0u8, addr1, Witness {});
    account_1.register<TestCurrency>(&auth, public_key(pk_1));

    // Register second account and deposit
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_with_witness<TestCurrency, Witness>(0u8, addr2, Witness {});
    account_2.register<TestCurrency>(&auth, public_key(pk_2));

    // Mint some coins and add them to the accounts' encrypted balances.
    scenario.next_tx(addr1);

    let mut pool: contra::Pool<TestCurrency> = scenario.take_shared();

    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(
        &auth,
        &ct,
        &deny_list,
        &pool,
        coins,
        vector[],
    );

    account_1.merge<TestCurrency>(&auth);
    scenario.next_tx(addr1);

    // Take some from the balance of account 1 and deposit to account 2.
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, 10097),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let r = 32533; // Randomness for the trivial encryptions of the transferred amount below.
    let elgamal_dst = account_1.dst_elgamal_for_testing<TestCurrency>();
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let total_sender = sender_amount.collapse();

    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &old_balance,
        &new_balance.collapse(),
        &total_sender,
        &sk_1,
    );
    let receiver_consistency_proof = consistency_proof_for_testing(
        elgamal_dst,
        50,
        &receiver_amount,
        r,
        &pk_2,
    );
    let sender_consistency_proof = encrypted_amount::sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance,
        50,
        10097,
        &total_sender,
        50,
        r,
        &pk_1,
    );
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance,
        pk_2,
        receiver_amount,
        receiver_consistency_proof,
        sender_consistency_proof,
        *total_sender.decryption_handle(),
        sum_proof,
        &deny_list,
        scenario.ctx(),
    );

    scenario.next_tx(addr1);

    // Account 2 merges the pending deposit into its balance, merges and unwraps
    scenario.next_tx(addr2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.merge<TestCurrency>(&auth);

    // Account 2 takes 30 coins from its balance to self. This leaves 20 in the balance since Account 1 transfered 50.
    let taken_amount = 30;
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(20, &pk_2, 76520),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let mut zero = new_balance.collapse();
    zero.add_assign_u64(taken_amount);
    zero.sub_assign(&account_2.balance<TestCurrency>());
    let sum_proof = nizk::zero_proof_for_testing(
        account_2.dst_ddh_for_testing<TestCurrency>(),
        &zero,
        &sk_2,
    );
    let elgamal_dst_2 = account_2.dst_elgamal_for_testing<TestCurrency>();
    let new_balance_consistency_proof = consistency_proof_for_testing(
        elgamal_dst_2,
        20,
        &new_balance,
        76520,
        &pk_2,
    );
    let coins = account_2.unwrap(
        &auth,
        &ct,
        &deny_list,
        &mut pool,
        new_balance,
        new_balance_consistency_proof,
        range_proof::assume_range_checked(),
        taken_amount,
        &sum_proof,
        scenario.ctx(),
    );
    assert!(coins.value() == 30);

    unit_test::destroy(coins);
    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(_deny_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct);

    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);

    scenario.end();
}

#[test]
fun test_batched_transfer() {
    let setup_addr = @0x0;

    // Sender
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());

    // Receiver A
    let addr2 = @0x101;
    let sk_2 = ristretto255::scalar_from_u64(67890);
    let pk_2 = ristretto255::g_mul(&sk_2, &ristretto255::g_generator());

    // Receiver B
    let addr3 = @0x102;
    let sk_3 = ristretto255::scalar_from_u64(11111);
    let pk_3 = ristretto255::g_mul(&sk_3, &ristretto255::g_generator());

    // Setup scenario, deny list, registries, currency.
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
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    // Register all three accounts.
    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));

    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth, public_key(pk_2));

    scenario.next_tx(addr3);
    let mut account_3 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_3.register<TestCurrency>(&auth, public_key(pk_3));

    // Mint 100 coins to addr1 and merge into the active balance.
    scenario.next_tx(addr1);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(
        &auth,
        &ct,
        &deny_list,
        &pool,
        coins,
        vector[],
    );
    account_1.merge<TestCurrency>(&auth);
    scenario.next_tx(addr1);

    // Transfer 30 to addr2 and 20 to addr3 in a single batched transfer, leaving 50.
    let r_a = 32533;
    let r_b = 17000;

    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, 10097),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let taken_a_ea = amount_for_testing(30, &pk_2, r_a);
    let taken_b_ea = amount_for_testing(20, &pk_3, r_b);
    let elgamal_dst = account_1.dst_elgamal_for_testing<TestCurrency>();

    // One batched range proof covering [receiver_a, receiver_b, new_balance] under
    // [pk_2, pk_3, pk_1], constructed by the sender under their ELGAMAL DST.
    let receiver_consistency_proofs = vector[
        consistency_proof_for_testing(elgamal_dst, 30, &taken_a_ea, r_a, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 20, &taken_b_ea, r_b, &pk_3),
    ];

    // Sender-side amounts, encrypted under pk_1; their collapsed sum gives the single decryption
    // handle the chain needs (the commitment is reconstructed from the receiver amounts).
    let taken_a_sender = amount_for_testing(30, &pk_1, r_a);
    let taken_b_sender = amount_for_testing(20, &pk_1, r_b);

    // Balance proof: old_balance == new_balance + total.
    let old_balance = account_1.balance<TestCurrency>();
    let total_sender = taken_a_sender.collapse().add(&taken_b_sender.collapse());
    let sender_consistency_proof = encrypted_amount::sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance_ea,
        50,
        10097,
        &total_sender,
        50,
        r_a + r_b,
        &pk_1,
    );
    let balance_proof = nizk::sum_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &old_balance,
        &new_balance_ea.collapse(),
        &total_sender,
        &sk_1,
    );

    // Execute the batched transfer and finalize. `add` credits each receiver-keyed coin to its
    // receiver, in the same order as the receiver amounts.
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1
        .batched_transfer<TestCurrency>(
            &auth,
            &ct,
            &deny_list,
            vector[public_key(pk_2), public_key(pk_3)],
            vector[taken_a_ea, taken_b_ea],
            receiver_consistency_proofs,
            new_balance_ea,
            *total_sender.decryption_handle(),
            sender_consistency_proof,
            range_proof::assume_range_checked(),
            ristretto255::g_identity(),
            balance_proof,
            option::none(),
        )
        .add<TestCurrency>(&mut account_2, vector[], &deny_list)
        .add<TestCurrency>(&mut account_3, vector[], &deny_list)
        .finalize();

    // Verify balances:
    //  - sender has 50 encrypted under pk_1 in its active balance,
    //  - receiver A has 30 encrypted under pk_2 in its pending encrypted deposits,
    //  - receiver B has 20 encrypted under pk_3 in its pending encrypted deposits.
    assert_eq!(account_1.balance<TestCurrency>(), new_balance_ea.collapse());
    assert_eq!(account_2.pending_encrypted_balance<TestCurrency>(), taken_a_ea.collapse());
    assert_eq!(account_3.pending_encrypted_balance<TestCurrency>(), taken_b_ea.collapse());

    // Clean up.
    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
    unit_test::destroy(account_3);
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

/// Per-transfer auditing: the token has an auditor key, so the batched transfer must attach the two
/// u32-limb auditor handles per receiver and a batched auditor `ElGamalProof`. The proof is built
/// from the derived auditor encryptions and verified on chain against the current auditor key.
#[test]
fun test_batched_transfer_with_auditor() {
    let setup_addr = @0x0;

    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(67890),
        &ristretto255::g_generator(),
    );
    let addr3 = @0x102;
    let pk_3 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(11111),
        &ristretto255::g_generator(),
    );

    let auditor_pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(0xA1),
        &ristretto255::g_generator(),
    );

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

    // Token created with the auditor key enabled: every transfer carries a handle set for it.
    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[public_key(auditor_pk)],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth, public_key(pk_2));
    scenario.next_tx(addr3);
    let mut account_3 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_3.register<TestCurrency>(&auth, public_key(pk_3));

    scenario.next_tx(addr1);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);
    scenario.next_tx(addr1);

    let r_a = 32533;
    let r_b = 17000;
    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, 10097),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let taken_a_ea = amount_for_testing(30, &pk_2, r_a);
    let taken_b_ea = amount_for_testing(20, &pk_3, r_b);
    let elgamal_dst = account_1.dst_elgamal_for_testing<TestCurrency>();
    let receiver_consistency_proofs = vector[
        consistency_proof_for_testing(elgamal_dst, 30, &taken_a_ea, r_a, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 20, &taken_b_ea, r_b, &pk_3),
    ];

    let taken_a_sender = amount_for_testing(30, &pk_1, r_a);
    let taken_b_sender = amount_for_testing(20, &pk_1, r_b);
    let old_balance = account_1.balance<TestCurrency>();
    let total_sender = taken_a_sender.collapse().add(&taken_b_sender.collapse());
    let sender_consistency_proof = encrypted_amount::sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance_ea,
        50,
        10097,
        &total_sender,
        50,
        r_a + r_b,
        &pk_1,
    );
    let balance_proof = nizk::sum_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &old_balance,
        &new_balance_ea.collapse(),
        &total_sender,
        &sk_1,
    );

    // The auditor's handles + one witness-folded ElGamal proof over all auditor ciphertexts, for the
    // two receiver amounts (both limb-0-only). `prepare_auditor_data` checks the single proof.
    let auditor_dst = account_1.dst_auditor_elgamal_for_testing<TestCurrency>();
    let (handles, proof) = build_auditor_data(
        vector[30, 20],
        vector[r_a, r_b],
        &auditor_pk,
        auditor_dst,
    );
    let auditor_package = auditors::new_auditor_package(handles, proof);

    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1
        .batched_transfer<TestCurrency>(
            &auth,
            &ct,
            &deny_list,
            vector[public_key(pk_2), public_key(pk_3)],
            vector[taken_a_ea, taken_b_ea],
            receiver_consistency_proofs,
            new_balance_ea,
            *total_sender.decryption_handle(),
            sender_consistency_proof,
            range_proof::assume_range_checked(),
            ristretto255::g_identity(),
            balance_proof,
            option::some(auditor_package),
        )
        .add<TestCurrency>(&mut account_2, vector[], &deny_list)
        .add<TestCurrency>(&mut account_3, vector[], &deny_list)
        .finalize();

    assert_eq!(account_1.balance<TestCurrency>(), new_balance_ea.collapse());
    assert_eq!(account_2.pending_encrypted_balance<TestCurrency>(), taken_a_ea.collapse());
    assert_eq!(account_3.pending_encrypted_balance<TestCurrency>(), taken_b_ea.collapse());

    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
    unit_test::destroy(account_3);
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

/// Rotation-grace: after the issuer rotates the auditor key with a grace window
/// (`update_auditors([new], [old])`), a transfer whose auditor data was built under the outgoing
/// (`previous`) key still succeeds — it fails to verify under `current_pks` and is then accepted under
/// `previous_pks`, so in-flight transfers stay auditable across the rotation.
#[test]
fun test_batched_transfer_auditor_rotation_grace() {
    let setup_addr = @0x0;

    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(67890),
        &ristretto255::g_generator(),
    );
    let addr3 = @0x102;
    let pk_3 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(11111),
        &ristretto255::g_generator(),
    );

    let auditor_pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(0xA1),
        &ristretto255::g_generator(),
    );
    let new_auditor_pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(0xB2),
        &ristretto255::g_generator(),
    );

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

    // Token created with `auditor_pk`, then rotated to `new_auditor_pk` with a grace window: the old
    // key moves to `previous_pks` and still verifies in-flight transfers built against it.
    scenario.next_tx(addr1);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[public_key(auditor_pk)],
        scenario.ctx(),
    );
    ct.update_auditors(
        &management_cap,
        vector[public_key(new_auditor_pk)],
        vector[public_key(auditor_pk)],
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth, public_key(pk_2));
    scenario.next_tx(addr3);
    let mut account_3 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_3.register<TestCurrency>(&auth, public_key(pk_3));

    scenario.next_tx(addr1);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);
    scenario.next_tx(addr1);

    let r_a = 32533;
    let r_b = 17000;
    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, 10097),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let taken_a_ea = amount_for_testing(30, &pk_2, r_a);
    let taken_b_ea = amount_for_testing(20, &pk_3, r_b);
    let elgamal_dst = account_1.dst_elgamal_for_testing<TestCurrency>();
    let receiver_consistency_proofs = vector[
        consistency_proof_for_testing(elgamal_dst, 30, &taken_a_ea, r_a, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 20, &taken_b_ea, r_b, &pk_3),
    ];

    let taken_a_sender = amount_for_testing(30, &pk_1, r_a);
    let taken_b_sender = amount_for_testing(20, &pk_1, r_b);
    let old_balance = account_1.balance<TestCurrency>();
    let total_sender = taken_a_sender.collapse().add(&taken_b_sender.collapse());
    let sender_consistency_proof = encrypted_amount::sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance_ea,
        50,
        10097,
        &total_sender,
        50,
        r_a + r_b,
        &pk_1,
    );
    let balance_proof = nizk::sum_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &old_balance,
        &new_balance_ea.collapse(),
        &total_sender,
        &sk_1,
    );

    // Auditor data built under `auditor_pk` — now the previous key. It fails to verify under
    // `current_pks` (the new key) and is accepted under `previous_pks` within the grace.
    let (auditor_handles, auditor_proof) = build_auditor_data(
        vector[30, 20],
        vector[r_a, r_b],
        &auditor_pk,
        account_1.dst_auditor_elgamal_for_testing<TestCurrency>(),
    );
    let auditor_package = auditors::new_auditor_package(auditor_handles, auditor_proof);

    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1
        .batched_transfer<TestCurrency>(
            &auth,
            &ct,
            &deny_list,
            vector[public_key(pk_2), public_key(pk_3)],
            vector[taken_a_ea, taken_b_ea],
            receiver_consistency_proofs,
            new_balance_ea,
            *total_sender.decryption_handle(),
            sender_consistency_proof,
            range_proof::assume_range_checked(),
            ristretto255::g_identity(),
            balance_proof,
            option::some(auditor_package),
        )
        .add<TestCurrency>(&mut account_2, vector[], &deny_list)
        .add<TestCurrency>(&mut account_3, vector[], &deny_list)
        .finalize();

    assert_eq!(account_1.balance<TestCurrency>(), new_balance_ea.collapse());
    assert_eq!(account_2.pending_encrypted_balance<TestCurrency>(), taken_a_ea.collapse());
    assert_eq!(account_3.pending_encrypted_balance<TestCurrency>(), taken_b_ea.collapse());

    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
    unit_test::destroy(account_3);
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

// === Auditor presence policy ===
//
// At most one auditor key (each of `current_pks` / `previous_pks` holds ≤1). Auditing is disabled
// exactly when `current_pks` is empty. A transfer must carry auditor data iff auditing is enabled.
// These exercise `prepare_auditor_data`'s presence branches directly (they never read `receiver_amounts`,
// so an empty vector is fine).

fun test_key(): PublicKey {
    public_key(ristretto255::g_mul(&ristretto255::scalar_from_u64(7), &ristretto255::g_generator()))
}

/// Disabled auditing (empty key vectors) accepts a no-op transfer (no auditor data).
#[test]
fun auditor_disabled_accepts_no_data() {
    let auditor = auditors::new(vector[]);
    let amounts = vector<EncryptedCoin<TestCurrency>>[];
    let handles = auditors::prepare_auditor_data(
        &auditor,
        &amounts,
        option::none(),
        session_id::new(b"dst"),
    );
    assert!(handles.is_none());
    handles.destroy!(|a| a.destroy_empty());
    amounts.destroy_empty();
    unit_test::destroy(auditor);
}

/// Enabled auditing requires auditor data: a no-op transfer (no data) aborts.
#[test, expected_failure(abort_code = ::contra::auditors::EMissingAuditorData)]
fun auditor_enabled_requires_data() {
    let auditor = auditors::new(vector[test_key()]);
    let amounts = vector<EncryptedCoin<TestCurrency>>[];
    auditors::prepare_auditor_data(
        &auditor,
        &amounts,
        option::none(),
        session_id::new(b"dst"),
    ).destroy!(|a| a.destroy_empty());
    amounts.destroy_empty();
    unit_test::destroy(auditor);
}

/// Disabled auditing forbids auditor data: attaching a package aborts (both key sets empty).
#[test, expected_failure(abort_code = ::contra::auditors::EUnexpectedAuditorData)]
fun auditor_disabled_forbids_data() {
    let auditor = auditors::new(vector[]);
    let amounts = vector<EncryptedCoin<TestCurrency>>[];
    // A trivial (empty) package suffices: the presence check aborts before the proof is inspected.
    let package = auditors::new_auditor_package(vector[], nizk::default_elgamal_proof());
    auditors::prepare_auditor_data(
        &auditor,
        &amounts,
        option::some(package),
        session_id::new(b"dst"),
    ).destroy!(|a| a.destroy_empty());
    amounts.destroy_empty();
    unit_test::destroy(auditor);
}

/// Disable-with-grace (`current_pks` empty but `previous_pks` non-empty, no longer forbidden now that
/// the two sets need not be the same length): a no-op transfer is still accepted — no current keys
/// means no audit is required going forward.
#[test]
fun auditor_disable_grace_accepts_no_data() {
    let mut auditor = auditors::new(vector[test_key()]);
    auditors::update(&mut auditor, vector[], vector[test_key()]);
    let amounts = vector<EncryptedCoin<TestCurrency>>[];
    let handles = auditors::prepare_auditor_data(
        &auditor,
        &amounts,
        option::none(),
        session_id::new(b"dst"),
    );
    assert!(handles.is_none());
    handles.destroy!(|a| a.destroy_empty());
    amounts.destroy_empty();
    unit_test::destroy(auditor);
}

#[test, expected_failure]
fun test_deny_list() {
    let setup_addr = @0x0;

    // Setup addresses
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());

    // Account 1 sets up a new currency and creates a confidential token for it. Account 1 also registers itself in the account registry and adds the currency to its account.
    let mut scenario = sui::test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());
    scenario.next_tx(setup_addr);
    let mut deny_list: deny_list::DenyList = scenario.take_shared();

    let mut acc_reg = contra::new_account_registry_for_testing(scenario.ctx());
    let mut ct_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(scenario.ctx());
    let (mut builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        scenario.ctx(),
    );
    let mut deny_cap = builder.make_regulated(true, scenario.ctx());

    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));

    deny_list_v2_add<TestCurrency>(&mut deny_list, &mut deny_cap, addr1, scenario.ctx());

    let coins = t_cap.mint(100, scenario.ctx());

    // This should fail since the sender is on the deny list
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    account_1.wrap(
        &auth,
        &ct,
        &deny_list,
        &pool,
        coins,
        vector[],
    );

    unit_test::destroy(account_1);
    unit_test::destroy(acc_reg);
    unit_test::destroy(builder);
    unit_test::destroy(t_cap);
    unit_test::destroy(deny_cap);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);

    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);

    scenario.end();
}

#[allow(unused_mut_parameter)]
fun transfer<T>(
    sender: &mut contra::Account,
    receiver: &mut contra::Account,
    memo: vector<u8>,
    ct: &contra::ConfidentialToken<T>,
    new_balance: encrypted_amount::EncryptedAmount,
    receiver_pk: Element<G>,
    receiver_amount: encrypted_amount::EncryptedAmount,
    receiver_consistency_proof: nizk::ElGamalProof,
    sender_consistency_proof: nizk::ElGamalProof,
    total_sender_handle: Element<G>,
    balance_proof: nizk::DdhProof,
    deny_list: &deny_list::DenyList,
    ctx: &mut TxContext,
) {
    let auth = ct.authorize_as_sender(ctx);
    sender
        .batched_transfer<T>(
            &auth,
            ct,
            deny_list,
            vector[public_key(receiver_pk)],
            vector[receiver_amount],
            vector[receiver_consistency_proof],
            new_balance,
            total_sender_handle,
            sender_consistency_proof,
            range_proof::assume_range_checked(),
            ristretto255::g_identity(),
            balance_proof,
            option::none(),
        )
        .add<T>(receiver, memo, deny_list)
        .finalize();
}

/// Build the decryption handles and one witness-folded `ElGamalProof` over all auditor ciphertexts for
/// a batch of limb-0-only receiver amounts (values `values[i]`, limb-0 blindings `blindings[i]`) under
/// the single `auditor_pk`. Each amount's low u32 limb is the ciphertext `(r_i*g + v_i*h, r_i*auditor_pk)`
/// — its commitment is key-independent, so it equals the receiver's own u32 commitment — and its high
/// u32 limb is the zero ciphertext. The returned handles are one `[lo, hi]` pair per amount
/// (`[r_i*auditor_pk, identity]`), matching `prepare_auditor_data`, and the proof covers the `2N` ciphertexts
/// in receiver-major, limb-minor order.
fun build_auditor_data(
    values: vector<u64>,
    blindings: vector<u64>,
    auditor_pk: &Element<G>,
    dst: vector<u8>,
): (vector<vector<Element<G>>>, nizk::ElGamalProof) {
    let mut handles = vector[];
    let mut encryptions = vector[];
    let mut proof_values = vector[];
    let mut proof_blindings = vector[];
    values.length().do!(|i| {
        let lo = encrypt_trivial_for_testing(values[i], auditor_pk, blindings[i]);
        let hi = encrypt_trivial_for_testing(0, auditor_pk, 0);
        handles.push_back(vector[*lo.decryption_handle(), *hi.decryption_handle()]);
        encryptions.push_back(lo);
        encryptions.push_back(hi);
        proof_values.push_back(values[i]);
        proof_values.push_back(0);
        proof_blindings.push_back(blindings[i]);
        proof_blindings.push_back(0);
    });
    let proof = nizk::prove_elgamal(
        dst,
        auditor_pk,
        &encryptions,
        &proof_values,
        &proof_blindings,
        &ristretto255::scalar_from_u64(97531),
        &ristretto255::scalar_from_u64(86420),
    );
    (handles, proof)
}

/// Build a single-value `EncryptedAmount` (`value` in limb 0, zero elsewhere) under `pk`, with
/// limb 0 encrypted using blinding `r`.
fun amount_for_testing(value: u16, pk: &Element<G>, r: u64): encrypted_amount::EncryptedAmount {
    encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(value as u64, pk, r),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    )
}

/// Whole-account key rotation must rebind the stored balance handle to the new key: after rotating
/// from `pk_old` to `pk_new` (`pk_new != pk_old`) the on-chain handle becomes `r * pk_new` and the
/// account's public key is updated, so decryption with the new secret key succeeds.
#[test]
fun test_key_rotation_rebinds_balance_to_new_key() {
    let setup_addr = @0x0;
    let addr1 = @0x100;

    let sk_old = ristretto255::scalar_from_u64(11111);
    let pk_old = ristretto255::g_mul(&sk_old, &ristretto255::g_generator());
    let sk_new = ristretto255::scalar_from_u64(22222);
    let pk_new = ristretto255::g_mul(&sk_new, &ristretto255::g_generator());

    let mut scenario = sui::test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());
    scenario.next_tx(setup_addr);
    let deny_list_obj: deny_list::DenyList = scenario.take_shared();

    let mut acc_reg = contra::new_account_registry_for_testing(scenario.ctx());
    let mut ct_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(scenario.ctx());
    let (mut builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        scenario.ctx(),
    );
    let _deny_cap = builder.make_regulated(true, scenario.ctx());

    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_old));
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();

    // Install a known balance under pk_old with a known blinding `r`.
    let r = 99999;
    let r_scalar = ristretto255::scalar_from_u64(r);
    let balance_under_pk_old = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_old, r),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    contra::set_balance_by_issuer<TestCurrency>(
        &mut t_cap,
        &mut account_1,
        balance_under_pk_old,
    );
    let d_old = ristretto255::g_mul(&r_scalar, &pk_old);
    assert_eq!(*account_1.balance<TestCurrency>().decryption_handle(), d_old);

    // Construct the re-keyed handles -- same plaintext + blinding under pk_new -- and rotate: set the
    // account key (target), then `rekey_token_account` catches the token's balance up from token.pk to it.
    let batch_ddh_dst = account_1.dst_batch_ddh_for_testing<TestCurrency>();
    let d_new = ristretto255::g_mul(&r_scalar, &pk_new);
    let w = ristretto255::scalar_div(&sk_old, &sk_new); // = sk_new / sk_old
    let id = ristretto255::g_identity();
    // Re-key proof over (pk, limb-0 handle) -- the other limbs are zero (identity handles).
    let rekey_proof = nizk::prove_ddh(
        batch_ddh_dst,
        &w,
        &vector[pk_old, d_old, id, id, id],
        &vector[pk_new, d_new, id, id, id],
        &r_scalar,
    );
    let new_ea = amount_for_testing(50, &pk_new, r);

    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::set_default_pk_as_sender(
        &mut account_1,
        option::some(public_key(pk_new)),
        scenario.ctx(),
    );
    // The default key is now pk_new, but the token's balance still lags under pk_old.
    assert_eq!(account_1.default_pk(), option::some(pk_new));
    assert_eq!(account_1.token_public_key<TestCurrency>(), pk_old);
    contra::rekey_token_account<TestCurrency>(
        &mut account_1,
        &auth,
        public_key(pk_new),
        new_ea.decryption_handles_for_testing(),
        rekey_proof,
    );

    // The on-chain handle must now be bound to `pk_new` and the token caught up to the account key.
    assert_eq!(*account_1.balance<TestCurrency>().decryption_handle(), d_new);
    assert_eq!(account_1.token_public_key<TestCurrency>(), pk_new);

    unit_test::destroy(account_1);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(_deny_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct);

    sui::test_scenario::return_shared(deny_list_obj);
    sui::test_scenario::return_shared(pool);

    scenario.end();
}

/// `rekey_token_account` aborts on a bad re-key proof (here a wrong witness, standing in for a raced balance
/// whose handles no longer match), reverting the PTB — nothing is committed.
#[test, expected_failure(abort_code = ::contra::contra::ERekeyProofFailed)]
fun test_rekey_token_account_aborts_on_bad_proof() {
    let setup_addr = @0x0;
    let addr1 = @0x100;

    let sk_old = ristretto255::scalar_from_u64(11111);
    let pk_old = ristretto255::g_mul(&sk_old, &ristretto255::g_generator());
    let pk_new = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(22222),
        &ristretto255::g_generator(),
    );

    let mut scenario = sui::test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());
    scenario.next_tx(setup_addr);
    let deny_list_obj: deny_list::DenyList = scenario.take_shared();

    let mut acc_reg = contra::new_account_registry_for_testing(scenario.ctx());
    let mut ct_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(scenario.ctx());
    let (mut builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        scenario.ctx(),
    );
    let _deny_cap = builder.make_regulated(true, scenario.ctx());

    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_old));
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();

    let r = 99999;
    let r_scalar = ristretto255::scalar_from_u64(r);
    let balance_under_pk_old = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_old, r),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    contra::set_balance_by_issuer<TestCurrency>(&mut t_cap, &mut account_1, balance_under_pk_old);
    let d_old = ristretto255::g_mul(&r_scalar, &pk_old);

    // A re-key proof built with the wrong witness -- verification fails, standing in for a raced
    // balance the client's handles no longer match.
    let batch_ddh_dst = account_1.dst_batch_ddh_for_testing<TestCurrency>();
    let d_new = ristretto255::g_mul(&r_scalar, &pk_new);
    let wrong_w = ristretto255::scalar_from_u64(7);
    let id = ristretto255::g_identity();
    let bad_proof = nizk::prove_ddh(
        batch_ddh_dst,
        &wrong_w,
        &vector[pk_old, d_old, id, id, id],
        &vector[pk_new, d_new, id, id, id],
        &r_scalar,
    );
    let new_ea = amount_for_testing(50, &pk_new, r);

    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::set_default_pk_as_sender(
        &mut account_1,
        option::some(public_key(pk_new)),
        scenario.ctx(),
    );
    // Aborts here with `ERekeyProofFailed`.
    contra::rekey_token_account<TestCurrency>(
        &mut account_1,
        &auth,
        public_key(pk_new),
        new_ea.decryption_handles_for_testing(),
        bad_proof,
    );

    // Unreachable; included so the resource flow type-checks if the abort is removed.
    unit_test::destroy(account_1);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(_deny_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct);

    sui::test_scenario::return_shared(deny_list_obj);
    sui::test_scenario::return_shared(pool);

    scenario.end();
}

/// `try_rekey_token_account_and_unpause` soft-fails on a bad proof (token left stale — the normal not-yet-re-keyed
/// state) and succeeds on a good one (token caught up), without aborting either way. This is what lets
/// a rotation + re-keys ride in one PTB without pausing.
#[test]
fun test_try_rekey_token_account_soft_fails_then_succeeds() {
    let setup_addr = @0x0;
    let addr1 = @0x100;

    let sk_old = ristretto255::scalar_from_u64(11111);
    let pk_old = ristretto255::g_mul(&sk_old, &ristretto255::g_generator());
    let sk_new = ristretto255::scalar_from_u64(22222);
    let pk_new = ristretto255::g_mul(&sk_new, &ristretto255::g_generator());

    let mut scenario = sui::test_scenario::begin(setup_addr);
    deny_list::create_for_testing(scenario.ctx());
    scenario.next_tx(setup_addr);
    let deny_list_obj: deny_list::DenyList = scenario.take_shared();

    let mut acc_reg = contra::new_account_registry_for_testing(scenario.ctx());
    let mut ct_registry = contra::new_token_registry_for_testing(scenario.ctx());
    let mut coin_registry = coin_registry::create_coin_data_registry_for_testing(scenario.ctx());
    let (mut builder, mut t_cap) = coin_registry.new_currency<TestCurrency>(
        8,
        "_",
        "_",
        "_",
        "_",
        scenario.ctx(),
    );
    let _deny_cap = builder.make_regulated(true, scenario.ctx());

    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_old));
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();

    let r = 99999;
    let r_scalar = ristretto255::scalar_from_u64(r);
    let balance_under_pk_old = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_old, r),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    contra::set_balance_by_issuer<TestCurrency>(&mut t_cap, &mut account_1, balance_under_pk_old);
    let d_old = ristretto255::g_mul(&r_scalar, &pk_old);
    let d_new = ristretto255::g_mul(&r_scalar, &pk_new);

    let batch_ddh_dst = account_1.dst_batch_ddh_for_testing<TestCurrency>();
    let w = ristretto255::scalar_div(&sk_old, &sk_new); // = sk_new / sk_old
    let id = ristretto255::g_identity();
    let good_proof = nizk::prove_ddh(
        batch_ddh_dst,
        &w,
        &vector[pk_old, d_old, id, id, id],
        &vector[pk_new, d_new, id, id, id],
        &r_scalar,
    );
    let bad_proof = nizk::prove_ddh(
        batch_ddh_dst,
        &ristretto255::scalar_from_u64(7), // wrong witness
        &vector[pk_old, d_old, id, id, id],
        &vector[pk_new, d_new, id, id, id],
        &r_scalar,
    );
    let new_ea = amount_for_testing(50, &pk_new, r);

    let auth = ct.authorize_as_sender(scenario.ctx());
    contra::set_default_pk_as_sender(
        &mut account_1,
        option::some(public_key(pk_new)),
        scenario.ctx(),
    );
    // Pause the token for the rotation; a successful re-key resumes deposits.
    contra::set_accepts_encrypted_deposits<TestCurrency>(&mut account_1, &auth, false);

    // Bad proof: soft-fails, leaves the token stale (still under pk_old) and paused, no abort.
    contra::try_rekey_token_account_and_unpause<TestCurrency>(
        &mut account_1,
        &auth,
        public_key(pk_new),
        new_ea.decryption_handles_for_testing(),
        bad_proof,
    );
    assert_eq!(account_1.token_public_key<TestCurrency>(), pk_old);
    assert_eq!(*account_1.balance<TestCurrency>().decryption_handle(), d_old);
    assert!(!account_1.accepts_deposits<TestCurrency>());

    // Good proof: succeeds, token caught up to the account key and deposits resume.
    contra::try_rekey_token_account_and_unpause<TestCurrency>(
        &mut account_1,
        &auth,
        public_key(pk_new),
        new_ea.decryption_handles_for_testing(),
        good_proof,
    );
    assert_eq!(account_1.token_public_key<TestCurrency>(), pk_new);
    assert_eq!(*account_1.balance<TestCurrency>().decryption_handle(), d_new);
    assert!(account_1.accepts_deposits<TestCurrency>());

    unit_test::destroy(account_1);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(_deny_cap);
    unit_test::destroy(builder);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct);

    sui::test_scenario::return_shared(deny_list_obj);
    sui::test_scenario::return_shared(pool);

    scenario.end();
}

// === Account freeze tests ===

#[test, expected_failure(abort_code = ::contra::contra::EAuthorizationError)]
fun test_account_freeze_rejects_non_admin() {
    let setup_addr = @0x0;
    let user_addr = @0x100;
    let pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(12345),
        &ristretto255::g_generator(),
    );

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

    scenario.next_tx(setup_addr);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(&auth, public_key(pk));

    // user_addr is NOT in freeze_admins; this must abort.
    ct.account_freeze<TestCurrency>(&mut account_user, scenario.ctx());

    unit_test::destroy(account_user);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    scenario.end();
}

#[test, expected_failure(abort_code = ::contra::contra::ETransferDenied)]
fun test_account_freeze_blocks_wrap() {
    let setup_addr = @0x0;
    let admin_addr = @0xA;
    let user_addr = @0x100;
    let pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(12345),
        &ristretto255::g_generator(),
    );

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

    scenario.next_tx(setup_addr);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(&auth, public_key(pk));

    scenario.next_tx(admin_addr);
    ct.account_freeze<TestCurrency>(&mut account_user, scenario.ctx());

    scenario.next_tx(user_addr);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.wrap(
        &auth,
        &ct,
        &deny_list,
        &pool,
        coins,
        vector[],
    );

    unit_test::destroy(account_user);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);
    scenario.end();
}

#[test]
fun test_account_unfreeze_restores_wrap() {
    let setup_addr = @0x0;
    let admin_addr = @0xA;
    let user_addr = @0x100;
    let pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(12345),
        &ristretto255::g_generator(),
    );

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

    scenario.next_tx(setup_addr);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(&auth, public_key(pk));

    scenario.next_tx(admin_addr);
    ct.account_freeze<TestCurrency>(&mut account_user, scenario.ctx());
    assert!(account_user.account_is_frozen<TestCurrency>());
    contra::account_unfreeze<TestCurrency>(&t_cap, &mut account_user);
    assert!(!account_user.account_is_frozen<TestCurrency>());

    // Wrap should now succeed.
    scenario.next_tx(user_addr);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.wrap(
        &auth,
        &ct,
        &deny_list,
        &pool,
        coins,
        vector[],
    );

    unit_test::destroy(account_user);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);
    scenario.end();
}

#[test, expected_failure(abort_code = ::contra::contra::ETransferDenied)]
fun test_account_freeze_blocks_batched_transfer() {
    let setup_addr = @0x0;
    let admin_addr = @0xA;
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(67890),
        &ristretto255::g_generator(),
    );

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

    scenario.next_tx(setup_addr);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth, public_key(pk_2));

    scenario.next_tx(addr1);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);

    // Freeze the sender after they've established a balance.
    scenario.next_tx(admin_addr);
    ct.account_freeze<TestCurrency>(&mut account_1, scenario.ctx());

    // Build a transfer that would otherwise be valid.
    scenario.next_tx(addr1);
    let r = 32533;
    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, 10097),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let elgamal_dst = account_1.dst_elgamal_for_testing<TestCurrency>();
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let total_sender = sender_amount.collapse();
    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &old_balance,
        &new_balance_ea.collapse(),
        &total_sender,
        &sk_1,
    );
    let receiver_consistency_proof = consistency_proof_for_testing(
        elgamal_dst,
        50,
        &receiver_amount,
        r,
        &pk_2,
    );
    let sender_consistency_proof = encrypted_amount::sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance_ea,
        50,
        10097,
        &total_sender,
        50,
        r,
        &pk_1,
    );
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance_ea,
        pk_2,
        receiver_amount,
        receiver_consistency_proof,
        sender_consistency_proof,
        *total_sender.decryption_handle(),
        sum_proof,
        &deny_list,
        scenario.ctx(),
    );

    // Unreachable; included so the resource flow type-checks if the abort is removed.
    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);
    scenario.end();
}

#[test, expected_failure(abort_code = ::contra::contra::ETransferDenied)]
fun test_account_freeze_blocks_add_to_batch() {
    let setup_addr = @0x0;
    let admin_addr = @0xA;
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(67890),
        &ristretto255::g_generator(),
    );

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

    scenario.next_tx(setup_addr);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth, public_key(pk_2));

    scenario.next_tx(addr1);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);

    // Freeze the receiver, not the sender.
    scenario.next_tx(admin_addr);
    ct.account_freeze<TestCurrency>(&mut account_2, scenario.ctx());

    scenario.next_tx(addr1);
    let r = 32533;
    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, 10097),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let elgamal_dst = account_1.dst_elgamal_for_testing<TestCurrency>();
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let total_sender = sender_amount.collapse();
    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &old_balance,
        &new_balance_ea.collapse(),
        &total_sender,
        &sk_1,
    );
    let receiver_consistency_proof = consistency_proof_for_testing(
        elgamal_dst,
        50,
        &receiver_amount,
        r,
        &pk_2,
    );
    let sender_consistency_proof = encrypted_amount::sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance_ea,
        50,
        10097,
        &total_sender,
        50,
        r,
        &pk_1,
    );
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance_ea,
        pk_2,
        receiver_amount,
        receiver_consistency_proof,
        sender_consistency_proof,
        *total_sender.decryption_handle(),
        sum_proof,
        &deny_list,
        scenario.ctx(),
    );

    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);
    scenario.end();
}

/// A receiver that has an `Account` but no `TokenAccount<T>` can be registered by anyone (here the
/// sender) via `register_with_default_pk` on a permissionless token, keyed at the receiver's
/// `Account.default_pk`; the subsequent transfer then credits the deposit.
#[test]
fun test_transfer_after_register_with_default_pk() {
    let setup_addr = @0x0;
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(67890),
        &ristretto255::g_generator(),
    );

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

    scenario.next_tx(setup_addr);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));

    // account_2 has an `Account` with a default key set but is NOT registered for TestCurrency; on a
    // permissionless token anyone can register it on the owner's behalf up front.
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    contra::set_default_pk_as_sender(
        &mut account_2,
        option::some(public_key(pk_2)),
        scenario.ctx(),
    );
    contra::register_with_default_pk<TestCurrency>(&mut account_2, &ct);

    scenario.next_tx(addr1);
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);

    scenario.next_tx(addr1);
    let r = 32533;
    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, 10097),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let elgamal_dst = account_1.dst_elgamal_for_testing<TestCurrency>();
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let total_sender = sender_amount.collapse();
    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &old_balance,
        &new_balance_ea.collapse(),
        &total_sender,
        &sk_1,
    );
    let receiver_consistency_proof = consistency_proof_for_testing(
        elgamal_dst,
        50,
        &receiver_amount,
        r,
        &pk_2,
    );
    let sender_consistency_proof = encrypted_amount::sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance_ea,
        50,
        10097,
        &total_sender,
        50,
        r,
        &pk_1,
    );
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance_ea,
        pk_2,
        receiver_amount,
        receiver_consistency_proof,
        sender_consistency_proof,
        *total_sender.decryption_handle(),
        sum_proof,
        &deny_list,
        scenario.ctx(),
    );

    // The token account was created for account_2, keyed at its account key.
    assert_eq!(account_2.token_public_key<TestCurrency>(), pk_2);

    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);
    scenario.end();
}

/// `register_with_default_pk` aborts on a token whose registration (operation 0) is permissioned.
#[test, expected_failure(abort_code = ::contra::contra::ERegistrationNotPermissionless)]
fun test_register_with_default_pk_aborts_when_permissioned() {
    let setup_addr = @0x0;
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(67890),
        &ristretto255::g_generator(),
    );

    let mut scenario = sui::test_scenario::begin(setup_addr);
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

    scenario.next_tx(setup_addr);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    // Make registration (operation 0) permissioned.
    ct.set_policy<TestCurrency, Witness>(&mut t_cap, vector[0u8]);

    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    contra::set_default_pk_as_sender(
        &mut account_2,
        option::some(public_key(pk_2)),
        scenario.ctx(),
    );
    // Aborts: registration is not permissionless, so no `Auth`-free registration is allowed.
    contra::register_with_default_pk<TestCurrency>(&mut account_2, &ct);

    unit_test::destroy(account_2);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    scenario.end();
}

/// `try_register_with_default_pk` is idempotent: a second call on an already-registered token account
/// is a no-op rather than aborting, so concurrent permissionless registrations don't fight.
#[test]
fun test_try_register_with_default_pk_is_idempotent() {
    let setup_addr = @0x0;
    let addr2 = @0x101;
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(67890),
        &ristretto255::g_generator(),
    );

    let mut scenario = sui::test_scenario::begin(setup_addr);
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

    // Registration is left permissionless (no `set_policy`).
    scenario.next_tx(setup_addr);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );

    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(scenario.ctx().sender());
    contra::set_default_pk_as_sender(
        &mut account_2,
        option::some(public_key(pk_2)),
        scenario.ctx(),
    );

    // First call registers the token account under the default key.
    contra::try_register_with_default_pk<TestCurrency>(&mut account_2, &ct);
    assert_eq!(account_2.token_public_key<TestCurrency>(), pk_2);
    // Second call is a no-op (`register_with_default_pk` here would abort `ETokenAccountAlreadyRegistered`).
    contra::try_register_with_default_pk<TestCurrency>(&mut account_2, &ct);
    assert_eq!(account_2.token_public_key<TestCurrency>(), pk_2);

    unit_test::destroy(account_2);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    scenario.end();
}

#[test, expected_failure(abort_code = ::contra::contra::ETransferDenied)]
fun test_account_freeze_blocks_unwrap() {
    let setup_addr = @0x0;
    let admin_addr = @0xA;
    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
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

    scenario.next_tx(setup_addr);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(scenario.ctx().sender());
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth, public_key(pk_1));

    let mut pool: contra::Pool<TestCurrency> = scenario.take_shared();
    let coins = t_cap.mint(100, scenario.ctx());
    account_1.wrap(&auth, &ct, &deny_list, &pool, coins, vector[]);
    account_1.merge<TestCurrency>(&auth);

    scenario.next_tx(admin_addr);
    ct.account_freeze<TestCurrency>(&mut account_1, scenario.ctx());

    scenario.next_tx(addr1);
    let taken_amount = 30;
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(70, &pk_1, 76520),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let mut zero = new_balance.collapse();
    zero.add_assign_u64(taken_amount);
    zero.sub_assign(&account_1.balance<TestCurrency>());
    let sum_proof = nizk::zero_proof_for_testing(
        account_1.dst_ddh_for_testing<TestCurrency>(),
        &zero,
        &sk_1,
    );
    let elgamal_dst_1 = account_1.dst_elgamal_for_testing<TestCurrency>();
    let new_balance_consistency_proof = consistency_proof_for_testing(
        elgamal_dst_1,
        70,
        &new_balance,
        76520,
        &pk_1,
    );
    let auth = ct.authorize_as_sender(scenario.ctx());
    let coins = account_1.unwrap(
        &auth,
        &ct,
        &deny_list,
        &mut pool,
        new_balance,
        new_balance_consistency_proof,
        range_proof::assume_range_checked(),
        taken_amount,
        &sum_proof,
        scenario.ctx(),
    );

    unit_test::destroy(coins);
    unit_test::destroy(account_1);
    unit_test::destroy(acc_reg);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(management_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    unit_test::destroy(ct);
    sui::test_scenario::return_shared(deny_list);
    sui::test_scenario::return_shared(pool);
    scenario.end();
}

#[test]
fun verify_encrypted_amount_dst_match_succeeds() {
    let sk = ristretto255::scalar_from_u64(42);
    let pk = ristretto255::g_mul(&sk, &ristretto255::g_generator());

    let amount: u16 = 1234;
    let r: u64 = 7777;
    let dst = b"dst-match-21-byte-tag";

    let ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(amount as u64, &pk, r),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let proof = consistency_proof_for_testing(dst, amount, &ea, r, &pk);
    // Succeeds (does not abort) when the verifier uses the same ELGAMAL dst.
    let verified = encrypted_amount::verify_encrypted_amount(ea, public_key(pk), &proof, dst);
    encrypted_amount::verify_in_range(
        vector[verified],
        range_proof::assume_range_checked(),
        b"range-proof-dst-21byt",
    );
}

// === Identity-pk rejection ===
//
// Identity is the additive zero of the group; an identity public key trivializes the discrete-log
// statement `sk · g = pk` (the unique witness is `sk = 0`, which anyone has). That cascades
// through the ElGamal / DDH proofs into a soundness break. Every public key entering the protocol —
// the account default key (`set_default_pk_*`), a token's per-token key (`register`/`rekey_*`), and
// the auditor keys (`new_confidential_token`/`update_auditors`) — is wrapped through
// `twisted_elgamal::public_key`, the single boundary that rejects `pk = identity`.

#[test, expected_failure(abort_code = ::contra::twisted_elgamal::EIdentityPublicKey)]
fun public_key_rejects_identity() {
    public_key(ristretto255::g_identity());
}

#[test, expected_failure(abort_code = ::contra::encrypted_amount::EEncryptionProofFailed)]
fun verify_encrypted_amount_dst_mismatch_fails() {
    let sk = ristretto255::scalar_from_u64(42);
    let pk = ristretto255::g_mul(&sk, &ristretto255::g_generator());

    let amount: u16 = 1234;
    let r: u64 = 7777;
    let prover_dst = b"dst-A-prover-21-bytes";
    let verifier_dst = b"dst-B-verifier-21-byt";

    let ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(amount as u64, &pk, r),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let proof = consistency_proof_for_testing(prover_dst, amount, &ea, r, &pk);
    // Verifier uses a different dst, thus the Fiat-Shamir challenges diverge and the ElGamal
    // consistency check aborts.
    encrypted_amount::verify_encrypted_amount(ea, public_key(pk), &proof, verifier_dst);
}

/// The production `RangeProofs` constructor rejects an empty proof set, so a batch verified on chain
/// can never skip its range check (only the `#[test_only]` `assume_range_checked` produces an empty
/// set).
#[test, expected_failure(abort_code = ::contra::range_proof::ERangeProofRequired)]
fun empty_range_proofs_rejected() {
    range_proof::new_range_proofs(vector[]);
}

// === Policy tests ===

#[test]
fun with_witness_grants_only_the_permissioned_operation() {
    let owner = @0x100;
    let mut policy = policy::permissionless();
    policy::set<Witness>(&mut policy, vector[0u8, 3u8]);

    let auth = policy::with_witness<TestCurrency, Witness>(&policy, 3u8, owner, Witness {});
    assert!(auth.is_allowed(3u8));
    assert!(!auth.is_allowed(0u8));
    assert!(auth.is_authenticated(owner));
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun with_witness_rejects_permissionless_operation() {
    let mut policy = policy::permissionless();
    policy::set<Witness>(&mut policy, vector[0u8, 3u8]);

    // Operation 1 is not in the policy's permissioned set; the witness cannot mint an auth for it.
    let _auth = policy::with_witness<TestCurrency, Witness>(&policy, 1u8, @0x100, Witness {});
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun with_witness_rejects_empty_policy() {
    let policy = policy::permissionless();
    let _auth = policy::with_witness<TestCurrency, Witness>(&policy, 0u8, @0x100, Witness {});
}
