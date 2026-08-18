// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// End-to-end: an enclave signature → `guardian::authorize_transfer` / `authorize_unwrap` →
/// `contra::batched_transfer` / `unwrap`, over the matrix of guardian on/off × good/bad
/// signature × good/bad balance proof, plus contra's binding check against a wrongly bound auth.
#[test_only]
module guardian::guardian_e2e_tests;

use contra::{
    contra,
    encrypted_amount::{
        Self,
        EncryptedAmount,
        consistency_proof_for_testing,
        sender_consistency_proof_for_testing,
    },
    nizk,
    policy::Auth,
    twisted_elgamal::{Self, encrypt_trivial_for_testing, public_key, PublicKey}
};
use guardian::guardian::{Self, GuardianWitness};
use std::unit_test::{Self, assert_eq};
use sui::{coin_registry, deny_list, group_ops::Element, hash::blake2b256, ristretto255::{Self, G}};

/// `account_1`'s secret key: builds a valid balance proof.
const VALID_SK: u64 = 12345;
/// A different key (the receiver's): builds an invalid balance proof.
const INVALID_SK: u64 = 67890;

const PERMISSIONED_UNWRAP: u8 = 2;
const PERMISSIONED_TRANSFER: u8 = 3;

/// The sender (`account_1`) address.
const SENDER: address = @0x100;
/// The receiver (`account_2`) address.
const RECEIVER: address = @0x101;
/// The registry operator.
const ALICE: address = @0xA11CE;

/// The fixture enclave key (ed25519 seed `00..1f`) and its signatures over the
/// `GuardianRequest` for the harness's 50-transfer and 40-unwrap.
const ENCLAVE_PK: vector<u8> = x"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const ENC_PK: vector<u8> = x"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRANSFER_SIG: vector<u8> =
    x"5a01bf92a636c02c468cc1f370fc9a5728515af27120a1c9a6eaede5ecf9ba7c58bfe38c7626234bf69045ed76a3cf8d9d67a2854412fe621357d22c0d592b0e";
const UNWRAP_SIG: vector<u8> =
    x"e9afcd1d4cf3e5503c2a4661daf6d95c43968a89a02928419f07341601fc53fc9d6deed9be86ba4120c4794ab0cf56d088281ea361ccc897c242b5dc7e87aa00";
const BAD_SIG: vector<u8> =
    x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

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

/// Everything `execute_transfer` needs for a 50-transfer from `account_1` to a fresh receiver.
public struct TransferArgs {
    account_2: contra::Account,
    receiver_pks: vector<PublicKey>,
    receiver_amounts: vector<EncryptedAmount>,
    receiver_consistency_proofs: vector<nizk::ElGamalProof>,
    new_balance: EncryptedAmount,
    total_handle: Element<G>,
    sender_consistency_proof: nizk::ElGamalProof,
    balance_proof: nizk::DdhProof,
}

/// Everything `execute_unwrap` needs for a 40-unwrap from `account_1`.
public struct UnwrapArgs {
    new_balance: EncryptedAmount,
    new_balance_consistency_proof: nizk::ElGamalProof,
    amount: u64,
    balance_proof: nizk::DdhProof,
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

/// A harness whose token has TRANSFER and UNWRAP gated behind `W` if `gated`.
fun new_harness<W>(gated: bool): Harness {
    let setup_addr = @0x0;
    let pk_1 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(VALID_SK),
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

    scenario.next_tx(SENDER);
    let (mut ct, management_cap) = ct_registry.new<TestCurrency>(
        &mut t_cap,
        vector[],
        scenario.ctx(),
    );
    if (gated) {
        ct.set_policy<TestCurrency, W>(
            &mut t_cap,
            vector[PERMISSIONED_TRANSFER, PERMISSIONED_UNWRAP],
        );
    };

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

/// `authorize_as_sender` for `account_1`.
fun sender_auth(h: &mut Harness): Auth<TestCurrency> {
    h.ct.authorize_as_sender(h.scenario.ctx())
}

/// Build a 50-transfer from `account_1` to a fresh receiver (`RECEIVER`, sk `INVALID_SK`),
/// leaving 50. `balance_proof_sk` is the key the balance ZK proof is built with: `VALID_SK`
/// makes it valid; `INVALID_SK` breaks only the proof.
fun prepare_transfer(h: &mut Harness, balance_proof_sk: u64): TransferArgs {
    let pk_1 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(VALID_SK),
        &ristretto255::g_generator(),
    );
    let pk_2 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(INVALID_SK),
        &ristretto255::g_generator(),
    );
    let balance_sk = ristretto255::scalar_from_u64(balance_proof_sk);

    h.scenario.next_tx(RECEIVER);
    let mut account_2 = h.acc_reg.new(RECEIVER);
    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    account_2.register<TestCurrency>(&auth, public_key(pk_2));
    h.scenario.next_tx(SENDER);

    let r_xfer = 32533;
    let r_balance = 10097;
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(50, &pk_1, r_balance),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    let elgamal_dst = h
        .account_1
        .derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let receiver_amount = amount_for_testing(50, &pk_2, r_xfer);
    let receiver_consistency_proofs = vector[
        consistency_proof_for_testing(elgamal_dst, 50, &receiver_amount, r_xfer, &pk_2),
    ];
    // The sender-side total: same commitment as the receiver amount, handle under `pk_1`.
    let total_sender = amount_for_testing(50, &pk_1, r_xfer).collapse_for_testing();
    let sender_consistency_proof = sender_consistency_proof_for_testing(
        elgamal_dst,
        &new_balance,
        50,
        r_balance,
        &total_sender,
        50,
        r_xfer,
        &pk_1,
    );
    let balance_proof = nizk::sum_proof_for_testing(
        h.account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &h.account_1.balance<TestCurrency>(),
        &new_balance.collapse_for_testing(),
        &total_sender,
        &balance_sk,
    );
    TransferArgs {
        account_2,
        receiver_pks: vector[public_key(pk_2)],
        receiver_amounts: vector[receiver_amount],
        receiver_consistency_proofs,
        new_balance,
        total_handle: twisted_elgamal::decryption_handle_for_testing(&total_sender),
        sender_consistency_proof,
        balance_proof,
    }
}

/// Run the transfer in `args` under `auth` and check both balances moved.
fun execute_transfer(h: &mut Harness, args: TransferArgs, auth: Auth<TestCurrency>) {
    let TransferArgs {
        mut account_2,
        receiver_pks,
        receiver_amounts,
        receiver_consistency_proofs,
        new_balance,
        total_handle,
        sender_consistency_proof,
        balance_proof,
    } = args;
    let receiver_amount = receiver_amounts[0];
    h
        .account_1
        .batched_transfer<TestCurrency>(
            &auth,
            &h.ct,
            &h.deny_list,
            receiver_pks,
            receiver_amounts,
            receiver_consistency_proofs,
            new_balance,
            total_handle,
            sender_consistency_proof,
            encrypted_amount::assume_range_checked(),
            ristretto255::g_identity(),
            balance_proof,
            option::none(),
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

/// Build a 40-unwrap from `account_1`, leaving 60. `balance_proof_sk` as in `prepare_transfer`.
fun prepare_unwrap(h: &Harness, balance_proof_sk: u64): UnwrapArgs {
    let pk_1 = ristretto255::g_mul(
        &ristretto255::scalar_from_u64(VALID_SK),
        &ristretto255::g_generator(),
    );
    let balance_sk = ristretto255::scalar_from_u64(balance_proof_sk);
    let amount = 40;
    let new_balance = encrypted_amount::new_encrypted_amount(
        encrypt_trivial_for_testing(60, &pk_1, 76520),
        encrypt_zero(),
        encrypt_zero(),
        encrypt_zero(),
    );
    // `new_balance + amount - old_balance`: the old balance is the trivial `(100*H, id)`, so this
    // is the blinding-76520 encryption of zero under `pk_1`.
    let zero = encrypt_trivial_for_testing(0, &pk_1, 76520);
    let balance_proof = nizk::zero_proof_for_testing(
        h.account_1.derive_dst_for_testing<TestCurrency>(contra::protocol_id_ddh()),
        &zero,
        &balance_sk,
    );
    let elgamal_dst = h
        .account_1
        .derive_dst_for_testing<TestCurrency>(contra::protocol_id_elgamal());
    let new_balance_consistency_proof = consistency_proof_for_testing(
        elgamal_dst,
        60,
        &new_balance,
        76520,
        &pk_1,
    );
    UnwrapArgs { new_balance, new_balance_consistency_proof, amount, balance_proof }
}

/// Run the unwrap in `args` under `auth` and check the coin and balance.
fun execute_unwrap(h: &mut Harness, args: UnwrapArgs, auth: Auth<TestCurrency>) {
    let UnwrapArgs { new_balance, new_balance_consistency_proof, amount, balance_proof } = args;
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
            encrypted_amount::assume_range_checked(),
            amount,
            &balance_proof,
            ctx,
        );
    assert_eq!(coins.value(), amount);
    assert_eq!(h.account_1.balance<TestCurrency>(), new_balance.collapse_for_testing());
    unit_test::destroy(coins);
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

// === Guardian scenarios ===

/// Which entry point a scenario exercises.
public enum Flow has copy, drop {
    Transfer,
    Unwrap,
}

/// How the scenario obtains its `Auth<T>`.
public enum AuthKind has copy, drop {
    /// `authorize_as_sender`: no guardian involved.
    Sender,
    /// `guardian::authorize_*` with the fixture enclave's signature over this operation.
    ValidSig,
    /// `guardian::authorize_*` with a signature that does not verify.
    BadSig,
    /// A `StubWitness` `Auth` bound to some other operation's digest (contra's binding check).
    BoundToOtherOp,
    /// Guardian *and* `StubWitness` both required (e.g. guardian + rate limiter): valid sig, but
    /// only the guardian has endorsed.
    ValidSigOfTwo,
    /// As `ValidSigOfTwo`, joined with `StubWitness`'s auth for the same operation.
    ValidSigAndStub,
    /// Valid sig, but the sender's balance changes before execution, so the approval is stale.
    ValidSigStale,
}

/// A stand-in witness for minting an `Auth` bound to a wrong digest, which the guardian never
/// does.
public struct StubWitness has drop {}

/// A registry holding the fixture enclave key at slot 0.
fun registry(): guardian::GuardianRegistry<TestCurrency> {
    let mut ctx = tx_context::new_from_hint(ALICE, 0, 0, 0, 0);
    let mut registry = guardian::new_registry_for_testing(
        guardian::new_pcrs(x"00", x"01", x"02"),
        ALICE,
        &mut ctx,
    );
    registry.register_guardian_enclave_key_for_testing(ENCLAVE_PK, ENC_PK);
    registry
}

fun stub_auth(h: &Harness, operation: u8, digest: vector<u8>): Auth<TestCurrency> {
    h
        .ct
        .authorize_with_witness_bound<TestCurrency, StubWitness>(
            operation,
            SENDER,
            digest,
            StubWitness {},
        )
}

/// `auth` joined with `StubWitness`'s (unbound) auth for `operation`.
/// Wrap and merge one more coin into `account_1`, changing the active balance the binding
/// committed to.
fun bump_balance(h: &mut Harness) {
    let coins = h.t_cap.mint(1, h.scenario.ctx());
    let auth = h.ct.authorize_as_sender(h.scenario.ctx());
    h.account_1.wrap(&auth, &h.ct, &h.deny_list, &h.pool, coins, vector[]);
    h.account_1.merge<TestCurrency>(&auth);
}

fun join_stub(h: &Harness, auth: Auth<TestCurrency>, operation: u8): Auth<TestCurrency> {
    let stub = h
        .ct
        .authorize_with_witness<TestCurrency, StubWitness>(operation, SENDER, StubWitness {});
    h.ct.join(auth, stub)
}

fun approval(auth_kind: AuthKind, sig: vector<u8>): guardian::GuardianApproval {
    guardian::new_guardian_approval(
        0,
        match (auth_kind) {
            AuthKind::ValidSig |
            AuthKind::ValidSigOfTwo |
            AuthKind::ValidSigAndStub |
            AuthKind::ValidSigStale => sig,
            _ => BAD_SIG,
        },
    )
}

/// Run one flow: `guardian_enabled` gates TRANSFER/UNWRAP behind `GuardianWitness`;
/// `balance_proof_sk` is `VALID_SK` for a valid balance proof, `INVALID_SK` to break only it.
fun run_scenario(flow: Flow, guardian_enabled: bool, auth_kind: AuthKind, balance_proof_sk: u64) {
    // Before the harness: `new_from_hint` in `registry()` resets the global test tx sender.
    let registry = registry();
    let mut h = match (auth_kind) {
        AuthKind::BoundToOtherOp => new_harness<StubWitness>(true),
        _ => new_harness<GuardianWitness>(guardian_enabled),
    };
    match (auth_kind) {
        AuthKind::ValidSigOfTwo | AuthKind::ValidSigAndStub => {
            let ops = vector[PERMISSIONED_TRANSFER, PERMISSIONED_UNWRAP];
            h.ct.set_policy<TestCurrency, StubWitness>(&mut h.t_cap, ops);
        },
        _ => (),
    };
    let other_digest = blake2b256(&b"some other operation".to_string().into_bytes());
    match (flow) {
        Flow::Transfer => {
            let args = prepare_transfer(&mut h, balance_proof_sk);
            let auth = match (auth_kind) {
                AuthKind::Sender => sender_auth(&mut h),
                AuthKind::BoundToOtherOp => stub_auth(&h, PERMISSIONED_TRANSFER, other_digest),
                _ => registry.authorize_transfer<TestCurrency>(
                    &h.ct,
                    &h.account_1,
                    args.receiver_pks,
                    args.receiver_amounts,
                    args.new_balance,
                    approval(auth_kind, TRANSFER_SIG),
                ),
            };
            let auth = match (auth_kind) {
                AuthKind::ValidSigAndStub => join_stub(&h, auth, PERMISSIONED_TRANSFER),
                _ => auth,
            };
            if (auth_kind == AuthKind::ValidSigStale) bump_balance(&mut h);
            execute_transfer(&mut h, args, auth);
        },
        Flow::Unwrap => {
            let args = prepare_unwrap(&h, balance_proof_sk);
            let auth = match (auth_kind) {
                AuthKind::Sender => sender_auth(&mut h),
                AuthKind::BoundToOtherOp => stub_auth(&h, PERMISSIONED_UNWRAP, other_digest),
                _ => registry.authorize_unwrap<TestCurrency>(
                    &h.ct,
                    &h.account_1,
                    args.new_balance,
                    args.amount,
                    approval(auth_kind, UNWRAP_SIG),
                ),
            };
            let auth = match (auth_kind) {
                AuthKind::ValidSigAndStub => join_stub(&h, auth, PERMISSIONED_UNWRAP),
                _ => auth,
            };
            if (auth_kind == AuthKind::ValidSigStale) bump_balance(&mut h);
            execute_unwrap(&mut h, args, auth);
        },
    };
    unit_test::destroy(registry);
    destroy(h);
}

// === Guardian matrix ===
//
// Every row runs on both flows (Transfer and Unwrap). The signature is checked by the guardian
// before contra runs, and contra checks the auth before the proofs, so the first failing check
// is the error that surfaces.
//
// | guardian | auth              | balance proof | result                        |
// |----------|-------------------|---------------|-------------------------------|
// | off      | sender            | valid         | pass                          |
// | on       | valid sig         | valid         | pass                          |
// | off      | sender            | invalid       | EBalanceProofFailed           |
// | on       | valid sig         | invalid       | EBalanceProofFailed           |
// | on       | sender (no sig)   | valid         | contra::EAuthorizationError   |
// | on       | bad sig           | valid         | EApprovalSignatureMismatch    |
// | on       | bad sig           | invalid       | EApprovalSignatureMismatch    |
// | off      | valid sig         | valid         | policy::EAuthorizationError   |
// | stub     | bound to other op | valid         | policy::EAuthorizationError   |
// | on+stub  | valid sig + stub  | valid         | pass                          |
// | on+stub  | valid sig only    | valid         | contra::EAuthorizationError   |
// | on       | valid sig, stale  | valid         | policy::EAuthorizationError   |

// --- Passing ---

#[test]
fun disabled_sender_transfer_passes() {
    run_scenario(Flow::Transfer, false, AuthKind::Sender, VALID_SK)
}

#[test]
fun disabled_sender_unwrap_passes() {
    run_scenario(Flow::Unwrap, false, AuthKind::Sender, VALID_SK)
}

#[test]
fun enabled_valid_sig_transfer_passes() {
    run_scenario(Flow::Transfer, true, AuthKind::ValidSig, VALID_SK)
}

#[test]
fun enabled_valid_sig_unwrap_passes() {
    run_scenario(Flow::Unwrap, true, AuthKind::ValidSig, VALID_SK)
}

// --- Failing ---

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun disabled_sender_invalid_proof_transfer_fails() {
    run_scenario(Flow::Transfer, false, AuthKind::Sender, INVALID_SK)
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun disabled_sender_invalid_proof_unwrap_fails() {
    run_scenario(Flow::Unwrap, false, AuthKind::Sender, INVALID_SK)
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun enabled_valid_sig_invalid_proof_transfer_fails() {
    run_scenario(Flow::Transfer, true, AuthKind::ValidSig, INVALID_SK)
}

#[test, expected_failure(abort_code = ::contra::contra::EBalanceProofFailed)]
fun enabled_valid_sig_invalid_proof_unwrap_fails() {
    run_scenario(Flow::Unwrap, true, AuthKind::ValidSig, INVALID_SK)
}

#[test, expected_failure(abort_code = ::contra::contra::EAuthorizationError)]
fun enabled_sender_transfer_fails() {
    run_scenario(Flow::Transfer, true, AuthKind::Sender, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::contra::EAuthorizationError)]
fun enabled_sender_unwrap_fails() {
    run_scenario(Flow::Unwrap, true, AuthKind::Sender, VALID_SK)
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun enabled_bad_sig_transfer_fails() {
    run_scenario(Flow::Transfer, true, AuthKind::BadSig, VALID_SK)
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun enabled_bad_sig_unwrap_fails() {
    run_scenario(Flow::Unwrap, true, AuthKind::BadSig, VALID_SK)
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun enabled_bad_sig_invalid_proof_transfer_fails() {
    run_scenario(Flow::Transfer, true, AuthKind::BadSig, INVALID_SK)
}

#[test, expected_failure(abort_code = ::guardian::guardian::EApprovalSignatureMismatch)]
fun enabled_bad_sig_invalid_proof_unwrap_fails() {
    run_scenario(Flow::Unwrap, true, AuthKind::BadSig, INVALID_SK)
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun disabled_valid_sig_transfer_fails() {
    run_scenario(Flow::Transfer, false, AuthKind::ValidSig, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun disabled_valid_sig_unwrap_fails() {
    run_scenario(Flow::Unwrap, false, AuthKind::ValidSig, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun bound_to_other_op_transfer_fails() {
    run_scenario(Flow::Transfer, true, AuthKind::BoundToOtherOp, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun bound_to_other_op_unwrap_fails() {
    run_scenario(Flow::Unwrap, true, AuthKind::BoundToOtherOp, VALID_SK)
}

#[test]
fun two_witness_valid_sig_and_stub_transfer_passes() {
    run_scenario(Flow::Transfer, true, AuthKind::ValidSigAndStub, VALID_SK)
}

#[test]
fun two_witness_valid_sig_and_stub_unwrap_passes() {
    run_scenario(Flow::Unwrap, true, AuthKind::ValidSigAndStub, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::contra::EAuthorizationError)]
fun two_witness_valid_sig_only_transfer_fails() {
    run_scenario(Flow::Transfer, true, AuthKind::ValidSigOfTwo, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::contra::EAuthorizationError)]
fun two_witness_valid_sig_only_unwrap_fails() {
    run_scenario(Flow::Unwrap, true, AuthKind::ValidSigOfTwo, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun stale_approval_transfer_fails() {
    run_scenario(Flow::Transfer, true, AuthKind::ValidSigStale, VALID_SK)
}

#[test, expected_failure(abort_code = ::contra::policy::EAuthorizationError)]
fun stale_approval_unwrap_fails() {
    run_scenario(Flow::Unwrap, true, AuthKind::ValidSigStale, VALID_SK)
}
