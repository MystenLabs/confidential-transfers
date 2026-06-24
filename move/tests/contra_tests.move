// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module contra::contra_tests;

use contra::{
    auditors,
    contra,
    encrypted_amount::{Self, consistency_proof_for_testing},
    nizk,
    twisted_elgamal::{Self, encrypt_trivial_for_testing, encrypt_zero}
};
use std::unit_test::{Self, assert_eq};
use sui::{
    coin::deny_list_v2_add,
    coin_registry,
    deny_list,
    group_ops::Element,
    ristretto255::{Self, G, Scalar},
    test_scenario::ctx
};

/// Type for Currency creation.
public struct TestCurrency has key { id: UID }

public struct Witness has drop {}

#[test]
fun create_account() {
    let owner = @0x100;
    let ctx = &mut tx_context::dummy();
    let mut acc_reg = contra::new_account_registry_for_testing(ctx);
    let account = acc_reg.new(owner);

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
    let auditor_public_keys = vector<Element<G>>[];

    // Confidential token object.
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        auditor_public_keys,
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
    let auditor_public_keys = vector<Element<G>>[];

    scenario.next_tx(addr1);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        auditor_public_keys,
        scenario.ctx(),
    );
    ct.set_policy<TestCurrency, Witness>(&mut t_cap, vector[0u8]);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_with_witness<TestCurrency, Witness>(0u8, addr1, Witness {});
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_1,
        option::none(),
    );

    // Register second account and deposit
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2);
    let auth = ct.authorize_with_witness<TestCurrency, Witness>(0u8, addr2, Witness {});
    account_2.register<TestCurrency>(
        &auth,
        &ct,
        pk_2,
        option::none(),
    );

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
    let auditor_public_keys = vector<Element<G>>[];

    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        auditor_public_keys,
        scenario.ctx(),
    );

    // Register all three accounts.
    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_1,
        option::none(),
    );

    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(
        &auth,
        &ct,
        pk_2,
        option::none(),
    );

    scenario.next_tx(addr3);
    let mut account_3 = acc_reg.new(addr3);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_3.register<TestCurrency>(
        &auth,
        &ct,
        pk_3,
        option::none(),
    );

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
    let auditor_public_keys = vector<Element<G>>[];

    scenario.next_tx(addr1);
    let (ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        auditor_public_keys,
        scenario.ctx(),
    );
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_1,
        option::none(),
    );

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
    nizk::prove_elgamal(dst, sender_pk, &enc, value, r)
}

/// Build a `KeyEncryption` (one `MultiRecipientEncryption` per 32-bit limb of `sk`, the matching
/// `KeyConsistencyProof`, and an empty `range_proof` since Move tests can't generate real
/// Bulletproof bytes). `seed` is mixed into the per-limb blindings and prover nonces so callers
/// can produce distinct, deterministic test data.
fun build_key_encryption(
    sk: &Element<Scalar>,
    pk: &Element<G>,
    auditor_pks: &vector<Element<G>>,
    seed: u64,
    dst: vector<u8>,
): auditors::KeyEncryption {
    let limbs = nizk::scalar_to_limbs(sk);
    let n = limbs.length();
    let m = auditor_pks.length();
    let g = twisted_elgamal::g();
    let h = twisted_elgamal::h();

    let mut encryptions = vector[];
    let mut blindings = vector[];
    n.do!(|i| {
        let r = ristretto255::scalar_from_u64(seed + (i + 1) * 1_000_003);
        let u = ristretto255::scalar_from_u64(limbs[i] as u64);
        encryptions.push_back(
            twisted_elgamal::new_multi_recipient_encryption(
                ristretto255::g_add(
                    &ristretto255::g_mul(&r, &g),
                    &ristretto255::g_mul(&u, &h),
                ),
                vector::tabulate!(m, |j| ristretto255::g_mul(&r, &auditor_pks[j])),
            ),
        );
        blindings.push_back(r);
    });

    let mut a = vector[];
    let mut b = vector[];
    n.do!(|i| {
        a.push_back(ristretto255::scalar_from_u64(seed + (i + 1) * 7_777));
        b.push_back(ristretto255::scalar_from_u64(seed + (i + 1) * 9_991));
    });

    let proof = nizk::prove_key_consistency(
        dst,
        &limbs,
        pk,
        auditor_pks,
        &encryptions,
        &blindings,
        a,
        b,
    );
    auditors::new_key_encryption(encryptions, proof, vector[])
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

/// Build an `EncryptedAmount` encrypting `amount` under `pk` with limb-0 blinding `r` and a
/// matching test-only batch-of-1 `WellFormedProof`. Used for transfer receiver amounts and for
/// the `new_balance` that `set_public_key` requires when rotating the viewing-key encryption.
fun amount_and_proof_for_testing(
    amount: u16,
    pk: &Element<G>,
    r: u64,
    dst: vector<u8>,
): (encrypted_amount::EncryptedAmount, encrypted_amount::WellFormedProof) {
    let ea = amount_for_testing(amount, pk, r);
    let proof = consistency_proof_for_testing(dst, amount, &ea, r, pk);
    (ea, encrypted_amount::new_well_formed_proof_singleton_for_testing(proof))
}

/// Batched re-key proof for `set_public_key` when the public key is unchanged: with `old_pk = new_pk`
/// and the new balance byte-equal to the old, the witness `w = new_sk · old_sk⁻¹ = 1` and the proof
/// is just "the identity rekey." The balance is assumed limb-0-only (limb-0 blinding `r`; the other
/// limbs encrypt zero, so their handles are the identity).
fun self_handle_eq_proof_for_testing(
    pk: &Element<G>,
    r: u64,
    dst: vector<u8>,
): nizk::BatchedDdhProof {
    let r_scalar = ristretto255::scalar_from_u64(r);
    let d = ristretto255::g_mul(&r_scalar, pk);
    let id = ristretto255::g_identity();
    // Pair 0 is the public key; pairs 1..4 are the limb handles (only limb 0 is non-identity).
    let bases = vector[*pk, d, id, id, id];
    nizk::prove_batched_ddh(dst, &ristretto255::scalar_one(), &bases, &bases, &r_scalar)
}

#[test]
fun test_auditor_version_flow() {
    let setup_addr = @0x0;

    let addr1 = @0x100;
    let sk_1 = ristretto255::scalar_from_u64(12345);
    let pk_1 = ristretto255::g_mul(&sk_1, &ristretto255::g_generator());

    let addr2 = @0x101;
    let sk_2 = ristretto255::scalar_from_u64(67890);
    let pk_2 = ristretto255::g_mul(&sk_2, &ristretto255::g_generator());

    // Two auditors. Their secret keys do not need to leave this test; we only need the
    // encryption keys to drive the consistency proofs.
    let auditor_sk_1 = ristretto255::scalar_from_u64(0xA1);
    let auditor_sk_2 = ristretto255::scalar_from_u64(0xA2);
    let auditor_pks = vector[
        ristretto255::g_mul(&auditor_sk_1, &ristretto255::g_generator()),
        ristretto255::g_mul(&auditor_sk_2, &ristretto255::g_generator()),
    ];

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

    // Token initialised with no auditors.
    scenario.next_tx(addr1);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector<Element<G>>[],
        scenario.ctx(),
    );

    // Account 1 registers while there are no auditors -> placeholder VKE at version 0.
    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_1,
        option::none(),
    );
    assert_eq!(account_1.verified_key_encryption_version<TestCurrency>(), 0);
    assert!(!account_1.verified_key_encryption_is_set<TestCurrency>());

    // Issuer sets two auditor keys with bump_recommended_min=false; the rotation does not
    // bump the recommended floor, so older registrations are not even advisory-stale.
    ct.update_auditors<TestCurrency>(&management_cap, auditor_pks, false);

    // Account 2 registers after auditors are set -> VKE at version 1.
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2);
    let session_id_2 = contra::session_id<TestCurrency>(&account_2);
    let kc_dst_2 = contra::dst(session_id_2, contra::protocol_id_key_consistency());
    let key_encryption_2 = build_key_encryption(&sk_2, &pk_2, &auditor_pks, 200, kc_dst_2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register_internal<TestCurrency>(
        &auth,
        pk_2,
        ct.verify_key_encryption_for_testing(&pk_2, option::some(key_encryption_2), kc_dst_2),
        session_id_2,
    );
    assert_eq!(account_2.verified_key_encryption_version<TestCurrency>(), 1);
    assert!(account_2.verified_key_encryption_is_set<TestCurrency>());

    // Account 1 wraps 100, merges, then transfers 50 to account 2. Mixed versions are fine
    // because the chain does not enforce the recommended floor.
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

    let r_xfer = 32533;
    let r_balance = 10097;
    let new_balance_ea = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, r_balance),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let receiver_amount = amount_for_testing(50, &pk_2, r_xfer);
    let sender_amount = amount_for_testing(50, &pk_1, r_xfer);
    let consistency_proof = total_consistency_proof_for_testing(50, &pk_1, r_xfer, elgamal_dst);
    let old_balance = account_1.balance<TestCurrency>();
    let sum_proof = nizk::sum_proof_for_testing(
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &old_balance,
        &new_balance_ea.collapse(),
        &sender_amount.collapse(),
        &sk_1,
    );
    let well_formed_proofs = encrypted_amount::new_well_formed_proof_for_testing(vector[
        consistency_proof_for_testing(elgamal_dst, 50, &receiver_amount, r_xfer, &pk_2),
        consistency_proof_for_testing(elgamal_dst, 50, &new_balance_ea, r_balance, &pk_1),
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

    // Account 1 rotates its viewing-key encryption (same pk). After the transfer the active
    // balance is exactly the encryption we just constructed, so we can re-derive r.
    scenario.next_tx(addr1);

    let rotation_ea_1 = amount_for_testing(50, &pk_1, r_balance);
    let key_encryption_1 = build_key_encryption(
        &sk_1,
        &pk_1,
        &auditor_pks,
        100,
        account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_key_consistency()),
    );
    let batch_ddh_dst_1 = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_batch_ddh(),
    );
    let kc_dst_1 = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_key_consistency(),
    );
    let proof_1 = self_handle_eq_proof_for_testing(&pk_1, r_balance, batch_ddh_dst_1);
    let vke_1 = ct.verify_key_encryption_for_testing(
        &pk_1,
        option::some(key_encryption_1),
        kc_dst_1,
    );
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.set_public_key_internal<TestCurrency>(
        &auth,
        pk_1,
        rotation_ea_1.decryption_handles_for_testing(),
        proof_1,
        vke_1,
        batch_ddh_dst_1,
    );
    assert_eq!(account_1.verified_key_encryption_version<TestCurrency>(), 1);
    assert!(account_1.verified_key_encryption_is_set<TestCurrency>());

    // Account 2 merges its pending deposit and then rotates its viewing-key encryption.
    scenario.next_tx(addr2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.merge<TestCurrency>(&auth);
    // Account 2's balance is the limb-0-only amount it received under blinding `r_xfer`.
    let batch_ddh_dst_2 = account_2.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_batch_ddh(),
    );
    let kc_dst_2 = account_2.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_key_consistency(),
    );
    let rotation_ea_2 = amount_for_testing(50, &pk_2, r_xfer);
    let key_encryption_2_again = build_key_encryption(
        &sk_2,
        &pk_2,
        &auditor_pks,
        300,
        kc_dst_2,
    );
    let proof_2 = self_handle_eq_proof_for_testing(&pk_2, r_xfer, batch_ddh_dst_2);
    let vke_2 = ct.verify_key_encryption_for_testing(
        &pk_2,
        option::some(key_encryption_2_again),
        kc_dst_2,
    );
    account_2.set_public_key_internal<TestCurrency>(
        &auth,
        pk_2,
        rotation_ea_2.decryption_handles_for_testing(),
        proof_2,
        vke_2,
        batch_ddh_dst_2,
    );
    assert_eq!(account_2.verified_key_encryption_version<TestCurrency>(), 1);

    // Clean up.
    unit_test::destroy(account_1);
    unit_test::destroy(account_2);
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

/// Rotating from `pk_old` to `pk_new` (`pk_new != pk_old`) must overwrite the on-chain
/// balance with `new_balance` so the stored decryption handle becomes `r * pk_new` instead
/// of `r * pk_old`. Without that overwrite, decryption with the new secret key would fail.
/// The other rotation in `test_auditor_version_flow` reuses the same `pk`, so it cannot
/// catch a regression here.
#[test]
fun test_set_public_key_replaces_balance_with_new_handle() {
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
        vector<Element<G>>[],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_old,
        option::none(),
    );
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

    // Construct `new_balance` -- same plaintext + blinding under pk_new -- and rotate.
    let batch_ddh_dst = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_batch_ddh(),
    );
    let kc_dst = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_key_consistency(),
    );
    let d_new = ristretto255::g_mul(&r_scalar, &pk_new);
    let w = ristretto255::scalar_div(&sk_old, &sk_new); // = sk_new / sk_old
    let id = ristretto255::g_identity();
    // Batched re-key proof over (pk, limb-0 handle) — the other limbs are zero (identity handles).
    let rekey_proof = nizk::prove_batched_ddh(
        batch_ddh_dst,
        &w,
        &vector[pk_old, d_old, id, id, id],
        &vector[pk_new, d_new, id, id, id],
        &r_scalar,
    );
    let new_ea = amount_for_testing(50, &pk_new, r);
    contra::set_public_key_internal<TestCurrency>(
        &mut account_1,
        &auth,
        pk_new,
        new_ea.decryption_handles_for_testing(),
        rekey_proof,
        ct.verify_key_encryption_for_testing(&pk_new, option::none(), kc_dst),
        batch_ddh_dst,
    );

    // The on-chain handle must now be bound to `pk_new`. Without the in-function
    // `token_account.balance.overwrite(&new_balance)`, this would still be
    // `r * pk_old` and decryption with `sk_new` would fail.
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

/// `try_set_public_key_and_unpause` unpauses only on a successful rotation: a failing rotation
/// leaves the account paused and unchanged, a valid one re-keys the balance and unpauses deposits.
#[test]
fun test_try_set_public_key_and_unpause() {
    let setup_addr = @0x0;
    let addr1 = @0x100;

    let sk_old = ristretto255::scalar_from_u64(11111);
    let pk_old = ristretto255::g_mul(&sk_old, &ristretto255::g_generator());
    let sk_new = ristretto255::scalar_from_u64(22222);
    let pk_new = ristretto255::g_mul(&sk_new, &ristretto255::g_generator());
    let w = ristretto255::scalar_div(&sk_old, &sk_new); // = sk_new / sk_old

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
        vector<Element<G>>[],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_old,
        option::none(),
    );
    let pool: contra::Pool<TestCurrency> = scenario.take_shared();

    // Pause deposits (the first half of a key rotation) and install a known balance of 50.
    contra::set_accepts_encrypted_deposits<TestCurrency>(
        &mut account_1,
        &auth,
        false,
    );
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

    let elgamal_dst = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_elgamal(),
    );
    let ddh_dst = account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh());
    let batch_ddh_dst = account_1.derive_dst_for_testing<TestCurrency>(
        contra::protocol_id_batch_ddh(),
    );

    // The re-key targets a fresh, client-known blinding `r_restate`; both `new_pk` handles below
    // are built against it.
    let r_restate = r + 7;
    let r_restate_scalar = ristretto255::scalar_from_u64(r_restate);
    let d_new = ristretto255::g_mul(&r_restate_scalar, &pk_new);
    let d_old_restate = ristretto255::g_mul(&r_restate_scalar, &pk_old);
    let id = ristretto255::g_identity();

    // A failing rotation: the restate's balance proof does not verify (here it is built with the
    // wrong key; in production a racing deposit would make it fail the same way). The account must
    // neither re-key nor unpause, and the re-key args are never reached.
    let (bad_restate_ea, bad_restate_proof) = amount_and_proof_for_testing(
        50,
        &pk_old,
        r_restate,
        elgamal_dst,
    );
    let bad_diff = encrypted_amount::collapse_for_testing(&bad_restate_ea).sub(
        &account_1.balance<TestCurrency>(),
    );
    let bad_balance_proof = nizk::zero_proof_for_testing(ddh_dst, &bad_diff, &sk_new);
    let bad_rekey_ea = amount_for_testing(50, &pk_new, r_restate);
    contra::try_set_public_key_and_unpause<TestCurrency>(
        &mut account_1,
        &auth,
        &ct,
        pk_new,
        bad_restate_ea,
        bad_restate_proof,
        bad_balance_proof,
        bad_rekey_ea.decryption_handles_for_testing(),
        nizk::prove_batched_ddh(
            batch_ddh_dst,
            &w,
            &vector[pk_old, d_old_restate, id, id, id],
            &vector[pk_new, d_new, id, id, id],
            &r_restate_scalar,
        ),
        option::none(),
    );
    assert_eq!(*account_1.balance<TestCurrency>().decryption_handle(), d_old);
    assert!(!account_1.accepts_deposits<TestCurrency>());

    // A valid rotation: the restate re-states value 50 under the fresh blinding `r_restate`, then
    // the re-key moves it to pk_new and unpauses deposits.
    let (restate_ea, restate_proof) = amount_and_proof_for_testing(
        50,
        &pk_old,
        r_restate,
        elgamal_dst,
    );
    let diff = encrypted_amount::collapse_for_testing(&restate_ea).sub(
        &account_1.balance<TestCurrency>(),
    );
    let balance_proof = nizk::zero_proof_for_testing(ddh_dst, &diff, &sk_old);
    let rekey_ea = amount_for_testing(50, &pk_new, r_restate);
    contra::try_set_public_key_and_unpause<TestCurrency>(
        &mut account_1,
        &auth,
        &ct,
        pk_new,
        restate_ea,
        restate_proof,
        balance_proof,
        rekey_ea.decryption_handles_for_testing(),
        nizk::prove_batched_ddh(
            batch_ddh_dst,
            &w,
            &vector[pk_old, d_old_restate, id, id, id],
            &vector[pk_new, d_new, id, id, id],
            &r_restate_scalar,
        ),
        option::none(),
    );
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
    let sk = ristretto255::scalar_from_u64(12345);
    let pk = ristretto255::g_mul(&sk, &ristretto255::g_generator());

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
        vector<Element<G>>[],
        scenario.ctx(),
    );

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(user_addr);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(
        &auth,
        &ct,
        pk,
        option::none(),
    );

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
    let sk = ristretto255::scalar_from_u64(12345);
    let pk = ristretto255::g_mul(&sk, &ristretto255::g_generator());

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
        vector<Element<G>>[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(user_addr);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(
        &auth,
        &ct,
        pk,
        option::none(),
    );

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
    let sk = ristretto255::scalar_from_u64(12345);
    let pk = ristretto255::g_mul(&sk, &ristretto255::g_generator());

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
        vector<Element<G>>[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(user_addr);
    let mut account_user = acc_reg.new(user_addr);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_user.register<TestCurrency>(
        &auth,
        &ct,
        pk,
        option::none(),
    );

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
    let sk_2 = ristretto255::scalar_from_u64(67890);
    let pk_2 = ristretto255::g_mul(&sk_2, &ristretto255::g_generator());

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
        vector<Element<G>>[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_1,
        option::none(),
    );
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(
        &auth,
        &ct,
        pk_2,
        option::none(),
    );

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
    let sk_2 = ristretto255::scalar_from_u64(67890);
    let pk_2 = ristretto255::g_mul(&sk_2, &ristretto255::g_generator());

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
        vector<Element<G>>[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_1,
        option::none(),
    );
    scenario.next_tx(addr2);
    let mut account_2 = acc_reg.new(addr2);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_2.register<TestCurrency>(
        &auth,
        &ct,
        pk_2,
        option::none(),
    );

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
        vector<Element<G>>[],
        scenario.ctx(),
    );
    ct.issue_freeze_cap<TestCurrency>(&management_cap, admin_addr);

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        pk_1,
        option::none(),
    );

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
// through the ElGamal / DDH / key-consistency proofs into a soundness break. The fix is to reject
// `pk = identity` at every install boundary: `register`, `set_public_key{,_internal}`, and the
// `auditors::{new,update}` calls that install the auditor key set.

#[test, expected_failure(abort_code = ::contra::contra::EIdentityPublicKey)]
fun register_rejects_identity_pk() {
    let setup_addr = @0x0;
    let addr1 = @0x100;

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
        vector<Element<G>>[],
        scenario.ctx(),
    );

    scenario.next_tx(addr1);
    let mut account_1 = acc_reg.new(addr1);
    // Identity pk: register must reject this.
    let auth = ct.authorize_as_sender(scenario.ctx());
    account_1.register<TestCurrency>(
        &auth,
        &ct,
        ristretto255::g_identity(),
        option::none(),
    );

    unit_test::destroy(account_1);
    unit_test::destroy(acc_reg);
    unit_test::destroy(ct);
    unit_test::destroy(management_cap);
    unit_test::destroy(t_cap);
    unit_test::destroy(builder);
    unit_test::destroy(_deny_cap);
    unit_test::destroy(ct_registry);
    unit_test::destroy(coin_registry);
    sui::test_scenario::return_shared(deny_list_obj);
    scenario.end();
}

#[test, expected_failure(abort_code = ::contra::auditors::EIdentityAuditorPublicKey)]
fun auditors_new_rejects_identity_pk() {
    let real_pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(123),
        &ristretto255::g_generator(),
    );
    unit_test::destroy(auditors::new(vector[real_pk, ristretto255::g_identity()]));
}

#[test, expected_failure(abort_code = ::contra::auditors::EIdentityAuditorPublicKey)]
fun auditors_update_rejects_identity_pk() {
    let real_pk = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(123),
        &ristretto255::g_generator(),
    );
    let mut auditors = auditors::new(vector[real_pk]);
    auditors.update(vector[real_pk, ristretto255::g_identity()], false);
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
