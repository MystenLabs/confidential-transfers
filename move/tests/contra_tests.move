// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module contra::contra_tests;

use contra::{
    auditors,
    contra,
    encrypted_amount::{Self, consistency_proof_for_testing},
    nizk,
    policy,
    twisted_elgamal::{encrypt_trivial_for_testing, encrypt_zero}
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
    let owner = @0x100;
    let pk = ristretto255::g_mul(&ristretto255::scalar_from_u64(7), &ristretto255::g_generator());
    let ctx = &mut tx_context::dummy();
    let mut acc_reg = contra::new_account_registry_for_testing(ctx);
    let account = acc_reg.new(owner, pk);

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
        option::none(),
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
        option::none(),
        scenario.ctx(),
    );
    ct.set_policy<TestCurrency, Witness>(&mut t_cap, vector[0u8]);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_with_witness<TestCurrency, Witness>(0u8, addr1, Witness {});
    account_1.register<TestCurrency>(&auth);

    // Register second account and deposit
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2, pk_2);
    let auth = ct.authorize_with_witness<TestCurrency, Witness>(0u8, addr2, Witness {});
    account_2.register<TestCurrency>(&auth);

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
    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r, elgamal_dst);

    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &old_balance,
        &new_balance.collapse(),
        &sender_amount.collapse(),
        &sk_1,
    );
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 50, &receiver_amount, r, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance, 10097, &pk_1),
    ]);
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance,
        pk_2,
        receiver_amount,
        well_formed_proofs,
        sender_amount,
        consistency_proof,
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
        account_2.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &zero,
        &sk_2,
    );
    let elgamal_dst_2 = account_2.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_elgamal(),
    );
    let new_balance_proof = encrypted_amount::new_well_formed_proof_singleton_for_testing(
        consistency_proof_for_testing(elgamal_dst_2, 20, &new_balance, 76520, &pk_2),
    );
    let coins = account_2.unwrap(
        &auth,
        &ct,
        &deny_list,
        &mut pool,
        new_balance,
        new_balance_proof,
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
        option::none(),
        scenario.ctx(),
    );

    // Register all three accounts.
    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);

    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2, pk_2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth);

    scenario.next_tx(addr3);
    let mut account_3 = acc_reg.new(addr3, pk_3);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_3.register<TestCurrency>(&auth);

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
    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());

    // One batched well-formed proof covering [receiver_a, receiver_b, new_balance] under
    // [pk_2, pk_3, pk_1], constructed by the sender under their ELGAMAL DST.
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 30, &taken_a_ea, r_a, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 20, &taken_b_ea, r_b, &pk_3),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance_ea, 10097, &pk_1),
    ]);

    // Sender-side amounts, encrypted under pk_1; their collapsed sum gives the single decryption
    // handle the chain needs (the commitment is reconstructed from the receiver amounts).
    let taken_a_sender = amount_for_testing(30, &pk_1, r_a);
    let taken_b_sender = amount_for_testing(20, &pk_1, r_b);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r_a + r_b, elgamal_dst);

    // Balance proof: old_balance == new_balance + total.
    let old_balance = account_1.balance<TestCurrency>();
    let total_sender = taken_a_sender.collapse().add(&taken_b_sender.collapse());
    let total_sender_handle = *total_sender.decryption_handle();
    let balance_proof = nizk::sum_proof_for_testing(
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
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
            vector[pk_2, pk_3],
            vector[taken_a_ea, taken_b_ea],
            well_formed_proofs,
            total_sender_handle,
            consistency_proof,
            ristretto255::g_identity(),
            new_balance_ea,
            balance_proof,
            option::none(),
            option::none(),
            scenario.ctx(),
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

    // Token created with an auditor key enabled.
    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        option::some(auditor_pk),
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2, pk_2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth);
    scenario.next_tx(addr3);
    let mut account_3 = acc_reg.new(addr3, pk_3);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_3.register<TestCurrency>(&auth);

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
    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 30, &taken_a_ea, r_a, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 20, &taken_b_ea, r_b, &pk_3),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance_ea, 10097, &pk_1),
    ]);

    let taken_a_sender = amount_for_testing(30, &pk_1, r_a);
    let taken_b_sender = amount_for_testing(20, &pk_1, r_b);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r_a + r_b, elgamal_dst);
    let old_balance = account_1.balance<TestCurrency>();
    let total_sender = taken_a_sender.collapse().add(&taken_b_sender.collapse());
    let total_sender_handle = *total_sender.decryption_handle();
    let balance_proof = nizk::sum_proof_for_testing(
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &old_balance,
        &new_balance_ea.collapse(),
        &total_sender,
        &sk_1,
    );

    // Auditor handles + batched proof for the two receiver amounts (both limb-0-only).
    let (auditor_handles, auditor_proof) = build_auditor_data(
        vector[30, 20],
        vector[r_a, r_b],
        &auditor_pk,
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_auditor_elgamal()),
    );

    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1
        .batched_transfer<TestCurrency>(
            &auth,
            &ct,
            &deny_list,
            vector[pk_2, pk_3],
            vector[taken_a_ea, taken_b_ea],
            well_formed_proofs,
            total_sender_handle,
            consistency_proof,
            ristretto255::g_identity(),
            new_balance_ea,
            balance_proof,
            option::some(auditor_handles),
            option::some(auditor_proof),
            scenario.ctx(),
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
        option::none(),
        scenario.ctx(),
    );
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);

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
    well_formed_proofs: encrypted_amount::WellFormedProof,
    sender_amount: encrypted_amount::EncryptedAmount,
    consistency_proof: nizk::ElGamalProof,
    balance_proof: nizk::DdhProof,
    deny_list: &deny_list::DenyList,
    ctx: &mut TxContext,
) {
    let auth = ct.authorize_as_sender(ctx);
    // The chain reconstructs the sender total's commitment from the receiver amounts and only needs
    // the single collapsed decryption handle; `P` (seed_point) is unverified on chain.
    let total_sender_handle = *sender_amount.collapse().decryption_handle();
    sender
        .batched_transfer<T>(
            &auth,
            ct,
            deny_list,
            vector[receiver_pk],
            vector[receiver_amount],
            well_formed_proofs,
            total_sender_handle,
            consistency_proof,
            ristretto255::g_identity(),
            new_balance,
            balance_proof,
            option::none(),
            option::none(),
            ctx,
        )
        .add<T>(receiver, memo, deny_list)
        .finalize();
}

/// Consistency proof for the collapsed sender total of a transfer: a value-`value` encryption
/// under `sender_pk` with blinding `r`, matching the total `try_split_batch` reconstructs from the
/// receiver commitments and the single sender decryption handle.
fun total_consistency_proof_for_testing(
    value: u64,
    sender_pk: &Element<G>,
    r: u64,
    dst: vector<u8>,
): nizk::ElGamalProof {
    let enc = encrypt_trivial_for_testing(value, sender_pk, r);
    nizk::prove_elgamal(
        dst,
        sender_pk,
        &vector[enc],
        &vector[value],
        &vector[r],
        &ristretto255::scalar_from_u64(1234),
        &ristretto255::scalar_from_u64(5678),
    )
}

/// Build the flattened per-transfer auditor handles and the batched auditor `ElGamalProof` for a
/// batch of limb-0-only receiver amounts (values `values[i]`, limb-0 blindings `blindings[i]`).
/// Each amount contributes two u32-limb auditor encryptions matching
/// `encrypted_amount::batch_auditor_encryptions`: the low half `(r*g + v*h, r*aud_pk)` and the high
/// half `(identity, identity)` (its committed value and blinding are both zero).
fun build_auditor_data(
    values: vector<u64>,
    blindings: vector<u64>,
    auditor_pk: &Element<G>,
    dst: vector<u8>,
): (vector<Element<G>>, nizk::ElGamalProof) {
    let mut handles = vector[];
    let mut encryptions = vector[];
    let mut messages = vector[];
    let mut blinds = vector[];
    values.length().do!(|i| {
        let low = encrypt_trivial_for_testing(values[i], auditor_pk, blindings[i]);
        handles.push_back(*low.decryption_handle());
        handles.push_back(ristretto255::g_identity());
        encryptions.push_back(low);
        encryptions.push_back(encrypt_zero());
        messages.push_back(values[i]);
        messages.push_back(0);
        blinds.push_back(blindings[i]);
        blinds.push_back(0);
    });
    let proof = nizk::prove_elgamal(
        dst,
        auditor_pk,
        &encryptions,
        &messages,
        &blinds,
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
        option::none(),
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_old);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);
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
    // account key (target), then `rekey_token` catches the token's balance up from token.pk to it.
    let batch_ddh_dst = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_batch_ddh(),
    );
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
    contra::set_account_key<TestCurrency>(&mut account_1, &auth, pk_new);
    // The account key is now pk_new, but the token's balance still lags under pk_old.
    assert_eq!(account_1.account_public_key(), pk_new);
    assert_eq!(account_1.token_public_key<TestCurrency>(), pk_old);
    contra::rekey_token<TestCurrency>(
        &mut account_1,
        &auth,
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

/// `rekey_token` aborts on a bad re-key proof (here a wrong witness, standing in for a raced balance
/// whose handles no longer match), reverting the PTB — nothing is committed.
#[test, expected_failure(abort_code = ::contra::contra::EAmountsEqualityProofFailed)]
fun test_rekey_token_aborts_on_bad_proof() {
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
        option::none(),
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_old);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);
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
    let batch_ddh_dst = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_batch_ddh(),
    );
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
    contra::set_account_key<TestCurrency>(&mut account_1, &auth, pk_new);
    // Aborts here with `EAmountsEqualityProofFailed`.
    contra::rekey_token<TestCurrency>(
        &mut account_1,
        &auth,
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

/// `try_rekey_token` soft-fails on a bad proof (returns `false`, token left stale — the normal
/// not-yet-re-keyed state) and succeeds on a good one (returns `true`, token caught up), without
/// aborting either way. This is what lets a rotation + re-keys ride in one PTB without pausing.
#[test]
fun test_try_rekey_token_soft_fails_then_succeeds() {
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
        option::none(),
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_old);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);
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

    let batch_ddh_dst = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_batch_ddh(),
    );
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
    contra::set_account_key<TestCurrency>(&mut account_1, &auth, pk_new);

    // Bad proof: soft-fails, leaves the token stale (still under pk_old), no abort.
    assert!(
        !contra::try_rekey_token<TestCurrency>(
            &mut account_1,
            &auth,
            new_ea.decryption_handles_for_testing(),
            bad_proof,
        ),
    );
    assert_eq!(account_1.token_public_key<TestCurrency>(), pk_old);
    assert_eq!(*account_1.balance<TestCurrency>().decryption_handle(), d_old);

    // Good proof: succeeds, token caught up to the account key.
    assert!(
        contra::try_rekey_token<TestCurrency>(
            &mut account_1,
            &auth,
            new_ea.decryption_handles_for_testing(),
            good_proof,
        ),
    );
    assert_eq!(account_1.token_public_key<TestCurrency>(), pk_new);
    assert_eq!(*account_1.balance<TestCurrency>().decryption_handle(), d_new);

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
        option::none(),
        scenario.ctx(),
    );

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(user_addr, pk);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(&auth);

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
        option::none(),
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(user_addr, pk);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(&auth);

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
        option::none(),
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(user_addr, pk);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(&auth);

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
        option::none(),
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2, pk_2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth);

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
    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r, elgamal_dst);
    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &old_balance,
        &new_balance_ea.collapse(),
        &sender_amount.collapse(),
        &sk_1,
    );
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 50, &receiver_amount, r, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance_ea, 10097, &pk_1),
    ]);
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance_ea,
        pk_2,
        receiver_amount,
        well_formed_proofs,
        sender_amount,
        consistency_proof,
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
        option::none(),
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2, pk_2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(&auth);

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
    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r, elgamal_dst);
    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &old_balance,
        &new_balance_ea.collapse(),
        &sender_amount.collapse(),
        &sk_1,
    );
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 50, &receiver_amount, r, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance_ea, 10097, &pk_1),
    ]);
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance_ea,
        pk_2,
        receiver_amount,
        well_formed_proofs,
        sender_amount,
        consistency_proof,
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

/// A transfer to a receiver that has an `Account` but no `TokenAccount<T>` (a permissionless token)
/// auto-creates the token account, keyed at the receiver's `Account.pk`, and credits the deposit.
#[test]
fun test_transfer_auto_registers_receiver() {
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
        option::none(),
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);

    // account_2 has an `Account` but is NOT registered for TestCurrency.
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2, pk_2);

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
    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let receiver_amount = amount_for_testing(50, &pk_2, r);
    let sender_amount = amount_for_testing(50, &pk_1, r);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r, elgamal_dst);
    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &old_balance,
        &new_balance_ea.collapse(),
        &sender_amount.collapse(),
        &sk_1,
    );
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 50, &receiver_amount, r, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance_ea, 10097, &pk_1),
    ]);
    transfer<TestCurrency>(
        &mut account_1,
        &mut account_2,
        vector[],
        &ct,
        new_balance_ea,
        pk_2,
        receiver_amount,
        well_formed_proofs,
        sender_amount,
        consistency_proof,
        sum_proof,
        &deny_list,
        scenario.ctx(),
    );

    // The token account was auto-created for account_2, keyed at its account key.
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
        option::none(),
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1, pk_1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(&auth);

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
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &zero,
        &sk_1,
    );
    let elgamal_dst_1 = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_elgamal(),
    );
    let new_balance_proof = encrypted_amount::new_well_formed_proof_singleton_for_testing(
        consistency_proof_for_testing(elgamal_dst_1, 70, &new_balance, 76520, &pk_1),
    );
    let auth = ct.authorize_as_sender(scenario.ctx());
    let coins = account_1.unwrap(
        &auth,
        &ct,
        &deny_list,
        &mut pool,
        new_balance,
        new_balance_proof,
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
fun verify_well_formed_proof_dst_match_succeeds() {
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
    let proof = encrypted_amount::new_well_formed_proof_singleton_for_testing(
        consistency_proof_for_testing(dst, amount, &ea, r, &pk),
    );
    assert!(
        encrypted_amount::verify(&proof, dst, b"range-proof-dst-21byt", &vector[ea], &vector[pk]),
    );
}

// === Identity-pk rejection ===
//
// Identity is the additive zero of the group; an identity public key trivializes the discrete-log
// statement `sk · g = pk` (the unique witness is `sk = 0`, which anyone has). That cascades
// through the ElGamal / DDH proofs into a soundness break. The fix is to reject `pk = identity` at
// every install boundary: `new_account` (the account key) and the `auditors::{new,update}` calls
// that install the auditor key.

#[test, expected_failure(abort_code = ::contra::contra::EIdentityPublicKey)]
fun new_account_rejects_identity_pk() {
    let owner = @0x100;
    let ctx = &mut tx_context::dummy();
    let mut acc_reg = contra::new_account_registry_for_testing(ctx);
    // Identity pk: account creation must reject this.
    let account = acc_reg.new(owner, ristretto255::g_identity());

    unit_test::destroy(account);
    unit_test::destroy(acc_reg);
}

#[test, expected_failure(abort_code = ::contra::auditors::EIdentityAuditorPublicKey)]
fun auditors_new_rejects_identity_pk() {
    unit_test::destroy(auditors::new(option::some(ristretto255::g_identity())));
}

#[test, expected_failure(abort_code = ::contra::auditors::EIdentityAuditorPublicKey)]
fun auditors_update_rejects_identity_pk() {
    let real_pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(123),
        &ristretto255::g_generator(),
    );
    let mut auditors = auditors::new(option::some(real_pk));
    auditors.update(option::some(ristretto255::g_identity()), 0);
    unit_test::destroy(auditors);
}

#[test]
fun verify_well_formed_proof_dst_mismatch_fails() {
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
    let proof = encrypted_amount::new_well_formed_proof_singleton_for_testing(
        consistency_proof_for_testing(prover_dst, amount, &ea, r, &pk),
    );
    // Verifier uses a different dst, thus the Fiat-Shamir challenges diverge and the ElGamal consistency check rejects.
    assert!(
        !encrypted_amount::verify(
            &proof,
            verifier_dst,
            b"range-proof-dst-21byt",
            &vector[ea],
            &vector[pk],
        ),
    );
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
