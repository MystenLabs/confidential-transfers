// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Confidential transfers on Sui.
///
/// Enables token transfers where amounts are encrypted using twisted ElGamal
/// encryption while remaining verifiable through zero-knowledge proofs.
///
/// ## Key Flows for the Token Issuer of public token type `T`:
/// 1. Create a new confidential token for a token type `T` (using the TreasuryCap), optionally
///    with an initial set of auditor public keys. Creation returns a `ManagementCap<T>`.
/// 2. Set the freeze admins who can freeze the token globally or specific accounts (via the
///    ManagementCap). Those admins may monitor the confidential token and freeze it or
///    individual accounts if necessary.
/// 3. Unfreeze the token globally or a specific account (using the TreasuryCap).
/// 4. Set the balance of an account directly, to emulate burn/seize (using the TreasuryCap).
/// 5. Freeze specific accounts via the token's deny list, using
///    `sui::coin::deny_list_v2_add` / `sui::coin::deny_list_v2_remove`. The deny list affects
///    both the public and the private coin; to freeze only the private coin, see items 2 and 3.
/// 6. Rotate or disable the auditor key set via `update_auditors` (using the ManagementCap).
///    Setting `bump_recommended_min` raises the auditors' `recommended_min_version` to the new
///    version, signalling to wallets that every user should refresh their key.
///    Passing an empty `public_keys` vector disables the auditor flow.
/// 7. [Advanced] Set the policy for the confidential token (using the TreasuryCap). Policies define
///    which operations are permissioned. Currently supported permissioned operations are:
///    - `register`: Register a token account for a token type `T`. E.g., caller ensures the user is
///      KYCed before registering an account. When set, also setting the public key for an account
///      is permissioned.
///    - `wrap`: Wrap a public coin into a private balance. E.g., caller ensures the funds passed
///      screening before wrapping.
///    - `unwrap`: Unwrap a private balance into a public coin. E.g., caller enforces rate limit on
///      exiting the system.
///    Additional permissioned operations may be added in the future.
///    Permissioned operations are customized flows that should be implemented by the issuer's
///    contract, and may not be supported by all clients/wallets.
///    The default policy is fully permissionless.
///
/// ## Key Flows for Users:
/// 1. Create an account for an address (needed once for all token types).
/// 2. Register a token account for a token type `T` with a public key `pk`. If the token has
///    auditors configured, the user must additionally provide the user's key encrypted to every
///    auditor public key in the current set, and a proof that the ciphertext encrypts its
///    secret key.
/// 3. Update the public key for a token account.
/// 4. Wrap a public coin into a confidential token, adding to the pending encrypted balance of an
///    account.
/// 5. Transfer an encrypted amount to two or more token accounts.
/// 6. Unwrap an encrypted amount from a token account and convert it to public coins.
///
/// ## Authentication:
/// Some functions require authorization via an `&Auth<T>` argument. Under the default
/// permissionless policy any `Auth<T>` is accepted; permissioning narrows which constructors
/// produce a valid `Auth<T>`. The caller constructs the `Auth<T>` via one of three constructors:
/// - `authorize_as_sender`: authenticates `ctx.sender()`. The standard path for end-user wallets
///   and permissionless operations.
/// - `authorize_as_object`: authenticates the address derived from a given object's `UID`. Use this
///   when access is controlled by a Move object (the holder of `&mut UID` proves ownership).
/// - `authorize_with_witness`: authenticates `owner` under a witness `W` required by the policy. Use
///   this to implement custom permissioned operations: the issuer's contract holds `W`, performs
///   its own checks (e.g. KYC, screening, rate limiting), and creates an `Auth<T>` for the
///   requested operation.
///
module contra::contra;

use contra::{
    auditors::{Auditors, VerifiedKeyEncryption, KeyEncryption, new as new_auditors},
    balance::{Self, EncryptedBalance, EncryptedCoin, PublicCoin},
    deny_list::{is_frozen, is_receiver_denied, is_sender_denied},
    encrypted_amount::{Self, EncryptedAmount, WellFormedProof},
    events,
    nizk::{DdhProof, ElGamalProof},
    policy::{Self, Auth, Policy}
};
use sui::{
    coin::{Self, Coin, TreasuryCap},
    deny_list::DenyList,
    derived_object,
    dynamic_field as df,
    group_ops::Element,
    ristretto255::{G, g_identity},
    vec_set::{Self, VecSet}
};

// === Errors ===

const EAccountAlreadyRegistered: u64 = 0;
const ETransferDenied: u64 = 1;
const EAuthorizationError: u64 = 2;
const ETokenAlreadyRegistered: u64 = 3;
const EPendingDepositsMustBeMerged: u64 = 4;
const EBalanceProofFailed: u64 = 5;
const EAllAmountsMustBeUsed: u64 = 6;
const EAmountsEqualityProofFailed: u64 = 7;
const EEmptyTransferBatch: u64 = 8;
const ETooManyReceivers: u64 = 9;
/// Recovery: transfer or update active balance.
const EBalancesFull: u64 = 10;
const EIdentityPublicKey: u64 = 11;
const EBatchTooLarge: u64 = 12;

// === Constants ===

/// Maximum receivers in one batched transfer, bounded so the `u8` receiver index (`next_index`) can't overflow.
const MAX_BATCH_RECIPIENTS: u64 = 255;

/// (Potentially) permissioned operations.
const PERMISSIONED_REGISTER: u8 = 0;
const PERMISSIONED_WRAP: u8 = 1;
const PERMISSIONED_UNWRAP: u8 = 2;

/// Protocol IDs for Fiat-Shamir domain separation.
/// Protocol-id `100` is also reserved by the ts-sdk for `PROTOCOL_VERIFIED_DEC`
const DST_DDH: u8 = 0x01;
const DST_ELGAMAL: u8 = 0x02;
const DST_KEY_CONSISTENCY: u8 = 0x03;
const DST_RANGE_PROOF_16: u8 = 0x04;
const DST_RANGE_PROOF_32: u8 = 0x05;
const DST_BATCH_DDH: u8 = 0x06;

// === Registries ===

/// Registry of tokens for confidential transactions. Each `ConfidentialToken`'s
/// UID is derived from this registry.
public struct TokenRegistry has key { id: UID }

/// Registry of accounts for confidential transactions. Each `Account`'s UID is
/// derived from this registry.
public struct AccountRegistry has key { id: UID }

// === Main Types ===

/// The representation of a confidential token. Each `ConfidentialToken` corresponds to a public
/// token type `T`.
public struct ConfidentialToken<phantom T> has key {
    id: UID,
    is_active: bool, // Global freeze capability.
    freeze_admins: VecSet<address>,
    policy: Option<Policy>,
    auditors: Auditors,
}

/// The representation of the pool of tokens of type `T` in circulation as confidential tokens.
/// Stored as a derived object of `ConfidentialToken<T>` to reduce contention on non-unwrap
/// operations.
/// Tokens are held at this object's address via Sui address balance to reduce contention on wrap
/// operations.
public struct Pool<phantom T> has key {
    id: UID,
}

/// Base account that stores token accounts as dynamic fields.
public struct Account has key {
    id: UID,
    owner: address,
}

/// A user's account for one confidential token.
public struct TokenAccount<phantom T> has store {
    pk: Element<G>,
    verified_key_encryption: VerifiedKeyEncryption,
    session_id: vector<u8>,
    is_frozen: bool,
    accepts_deposits: bool,
    active: EncryptedBalance<T>,
    pending: EncryptedBalance<T>,
    public_balance: PublicCoin<T>,
}

/// State machine for batched transfers from a single sender to multiple receivers.
/// Created by `batched_transfer`, consumed by calling `add` for each receiver then `finalize`.
public enum TransferBatch<phantom T> {
    /// The sender's balance proof failed. Subsequent `add` calls are no-ops; `try_finalize`
    /// returns `false` and `finalize` aborts.
    BalanceProofFailed,
    /// The balance proof succeeded. Holds the receiver-keyed `EncryptedCoin`s split off the
    /// sender's balance, one per transfer. `add_to_batch` pops one per receiver and credits it to
    /// their pending deposits. `seed_point` (= `P`) and `next_index` are carried
    /// only for the events: each `add_to_batch` emits `P` and the receiver's batch index so the
    /// sender can later re-derive that transfer's blinding (`seed = HKDF(sk * P)`) and recover the
    /// amount from the on-chain commitment, without any sender-keyed decryption handle. `sender_pk`
    /// is likewise carried only for the event.
    Ok {
        sender: address,
        sender_pk: Element<G>,
        coins: vector<EncryptedCoin<T>>,
        seed_point: Element<G>,
        next_index: u8,
    },
}

// === Keys ===

/// Key used for `ConfidentialToken` UID derivation.
public struct TokenKey<phantom T>() has copy, drop, store;

/// Key used for `Pool` UID derivation from `ConfidentialToken`.
/// There is only one pool per token, so no parameter is needed.
public struct PoolKey() has copy, drop, store;

/// Dynamic field key used for storing `TokenAccount`s in `Account`.
public struct TokenAccountKey<phantom T>() has copy, drop, store;

/// Key used for `Account` UID derivation.
public struct AccountKey(address) has copy, drop, store;

// === Caps ===

/// Capability granting management of the freeze admins and auditor keys.
public struct ManagementCap<phantom T> has key, store { id: UID }

// === Init ===

/// On initialization, we create and share the `AccountRegistry` and `TokenRegistry` objects.
fun init(ctx: &mut TxContext) {
    let account_registry = AccountRegistry { id: object::new(ctx) };
    let token_registry = TokenRegistry { id: object::new(ctx) };
    transfer::share_object(account_registry);
    transfer::share_object(token_registry);
}

// === Authorization ===

/// Create an `Auth<T>` for `ctx.sender()` covering every operation the policy on `ct` leaves
/// permissionless.
public fun authorize_as_sender<T>(ct: &ConfidentialToken<T>, ctx: &TxContext): Auth<T> {
    policy::as_sender<T>(&ct.policy, ctx)
}

/// Create an `Auth<T>` on behalf of `owner` covering the requested `operation`, authorized by
/// witness `W`. Aborts unless the policy on `ct` is set, its witness type is `W`, and `operation`
/// is permissioned. The witness-holding contract is fully responsible for authenticating `owner`.
public fun authorize_with_witness<T, W: drop>(
    ct: &ConfidentialToken<T>,
    operation: u8,
    owner: address,
    witness: W,
): Auth<T> {
    policy::with_witness<T, W>(&ct.policy, operation, owner, witness)
}

/// Create an `Auth<T>` on behalf of an object identified by `uid`, covering every operation the
/// policy on `ct` leaves permissionless. Holding `&mut UID` proves custody of the object, so the
/// object self-authenticates as its own `owner` (the address derived from the UID).
public fun authorize_as_object<T>(ct: &ConfidentialToken<T>, uid: &mut UID): Auth<T> {
    policy::as_object<T>(&ct.policy, uid)
}

// === Creation Flows ===

public use fun new_confidential_token as TokenRegistry.new;
public use fun share_confidential_token as ConfidentialToken.share;

/// Create a new confidential token for the given token type. Can only happen
/// once per token type, and the token object is immediately shared.
///
/// Requires a `&mut TreasuryCap` for authorization, this is to prevent frozen
/// TreasuryCaps from being used.
///
/// Creates an `Auditors` object for the confidential token using the provided public keys.
/// The auditor public keys can be empty initially and updated later by the issuer.
///
/// Returns the created `ConfidentialToken` and a `ManagementCap` that can be used to perform
/// administrative operations for this token.
public fun new_confidential_token<T>(
    registry: &mut TokenRegistry,
    _t: &mut TreasuryCap<T>,
    auditor_public_keys: vector<Element<G>>,
    ctx: &mut TxContext,
): (ConfidentialToken<T>, ManagementCap<T>) {
    assert!(!derived_object::exists(&registry.id, TokenKey<T>()), ETokenAlreadyRegistered);
    let mut id = derived_object::claim(&mut registry.id, TokenKey<T>());
    let pool_id = derived_object::claim(&mut id, PoolKey());
    transfer::share_object(Pool<T> { id: pool_id });
    events::emit_new_confidential_token<T>();
    (
        ConfidentialToken<T> {
            id,
            is_active: true,
            freeze_admins: vec_set::empty(),
            policy: policy::permissionless(),
            auditors: new_auditors(auditor_public_keys),
        },
        ManagementCap { id: object::new(ctx) },
    )
}

/// Share the confidential token object.
/// This is needed to allow the issuer to interact with the confidential token, e.g.,
/// to set permissions, in the same PTB.
public fun share_confidential_token<T>(ct: ConfidentialToken<T>) {
    transfer::share_object(ct);
}

public use fun new_account as AccountRegistry.new;

/// Create a new account for the given address. Can only happen once per address.
///
/// Note: the `owner` argument is not tied to `ctx.sender()` — anyone can create an
/// `Account` on behalf of any address. Since `Account` has `key` only (no `store`),
/// the only way to dispose of it outside this module is via `share_account`, and
/// all authenticated operations still gate on `account.owner == ctx.sender()`.
public fun new_account(registry: &mut AccountRegistry, owner: address): Account {
    assert!(!derived_object::exists(&registry.id, AccountKey(owner)), EAccountAlreadyRegistered);
    let id = derived_object::claim(&mut registry.id, AccountKey(owner));
    Account { id, owner }
}

/// Share the account object.
/// This has do be done after `new_account`, but it allows the user to create token
/// accounts for confidential tokens immediately.
public fun share_account(account: Account) {
    transfer::share_object(account);
}

/// Create a `TokenAccount` for token `T` with the given `pk`. Authorized by `auth`, which must
/// be for the `PERMISSIONED_REGISTER` operation and for `account.owner`.
/// If `ConfidentialToken<T>` has auditors enabled, a `KeyEncryption` must be provided.
public fun register<T>(
    account: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    pk: Element<G>,
    key_encryption: Option<KeyEncryption>,
) {
    let session_id = account.session_id<T>();
    let verified_key_encription = ct
        .auditors
        .verify_key_encryption(
            &pk,
            key_encryption,
            session_id.dst(DST_KEY_CONSISTENCY),
            session_id.dst(DST_RANGE_PROOF_32),
        );

    register_internal(
        account,
        auth,
        pk,
        verified_key_encription,
        session_id,
    );
}

public(package) fun register_internal<T>(
    account: &mut Account,
    auth: &Auth<T>,
    pk: Element<G>,
    verified_key_encryption: VerifiedKeyEncryption,
    session_id: vector<u8>,
) {
    assert!(auth.is_allowed(PERMISSIONED_REGISTER), EAuthorizationError);
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    assert!(!account.has_token<T>(), EAccountAlreadyRegistered);
    assert!(pk != g_identity(), EIdentityPublicKey);

    events::emit_new_registration<T>(account.owner, pk, verified_key_encryption);

    df::add(
        &mut account.id,
        TokenAccountKey<T>(),
        TokenAccount<T> {
            pk,
            verified_key_encryption,
            session_id,
            is_frozen: false,
            accepts_deposits: true,
            active: balance::new<T>(),
            pending: balance::empty<T>(),
            public_balance: balance::zero<T>(),
        },
    );
}

/// Set whether this account for token `T` accepts new encrypted deposits.
/// This is used to prevent receiving new encrypted deposits during token account key rotation.
/// Authorized by `auth`, which must be for `account.owner`. Any `Auth<T>` is accepted regardless
/// of which operation it covers.
public fun set_accepts_encrypted_deposits<T>(
    account: &mut Account,
    auth: &Auth<T>,
    accepts_encrypted_deposits: bool,
) {
    // TODO: consider checking PERMISSIONED_REGISTER
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    account[TokenAccountKey<T>()].accepts_deposits = accepts_encrypted_deposits;
}

/// Update the public key for the account of token `T`. Authorized by `auth`, which must be for
/// the `PERMISSIONED_REGISTER` operation and for `account.owner` -- key rotation reuses the registration
/// authorization since the same flow gates account onboarding.
/// This aborts if there are pending deposits that need to be merged, so the caller should:
/// - Call `merge` to merge pending deposits and `set_accepts_encrypted_deposits` to false to
///   prevent new encrypted deposits.
/// - Call `set_public_key` to update the public key and `set_accepts_encrypted_deposits` to true
///   to allow new encrypted deposits again.
public fun set_public_key<T>(
    account: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    new_pk: Element<G>,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
    key_encryption: Option<KeyEncryption>,
) {
    let sid = account[TokenAccountKey<T>()].session_id;
    set_public_key_internal(
        account,
        auth,
        new_pk,
        new_handles,
        rekey_proof,
        ct
            .auditors
            .verify_key_encryption(
                &new_pk,
                key_encryption,
                sid.dst(DST_KEY_CONSISTENCY),
                sid.dst(DST_RANGE_PROOF_32),
            ),
        sid.dst(DST_BATCH_DDH),
    );
}

/// Optimistic key rotation: re-state the balance under a fresh blinding, re-key it to `new_pk`, and
/// unpause. If the restate's `balance_proof` fails (e.g. a deposit raced the caller's read), emits
/// `TrySetPublicKeyFailedEvent` and leaves the account paused for a retry. The caller must `merge`
/// (and pause) first.
public fun try_set_public_key_and_unpause<T>(
    account: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    new_pk: Element<G>,
    restated_balance: EncryptedAmount,
    restated_balance_proof: WellFormedProof,
    balance_proof: DdhProof,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
    key_encryption: Option<KeyEncryption>,
) {
    assert!(auth.is_allowed(PERMISSIONED_REGISTER), EAuthorizationError);
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);

    // Optimistic restate under the old key — the only step that can fail on a race. On failure we
    // bail before touching the key, leaving the account paused and merged for a retry.
    let token_account = &mut account[TokenAccountKey<T>()];
    let sid = token_account.session_id;
    let update_successful = token_account.try_update_active(
        restated_balance,
        restated_balance_proof,
        &balance_proof,
        sid,
    );

    if (!update_successful) {
        events::emit_try_set_public_key_failed();
        return
    };

    set_public_key_internal(
        account,
        auth,
        new_pk,
        new_handles,
        rekey_proof,
        ct
            .auditors
            .verify_key_encryption(
                &new_pk,
                key_encryption,
                sid.dst(DST_KEY_CONSISTENCY),
                sid.dst(DST_RANGE_PROOF_32),
            ),
        sid.dst(DST_BATCH_DDH),
    );
    account[TokenAccountKey<T>()].accepts_deposits = true;
}

/// Re-key the active balance to `new_pk`, aborting if any proof or precondition fails.
public(package) fun set_public_key_internal<T>(
    account: &mut Account,
    auth: &Auth<T>,
    new_pk: Element<G>,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
    new_verified_key_encryption: VerifiedKeyEncryption,
    dst: vector<u8>,
) {
    assert!(auth.is_allowed(PERMISSIONED_REGISTER), EAuthorizationError);
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    assert!(new_pk != g_identity(), EIdentityPublicKey);
    let owner = account.owner;
    let token_account = &mut account[TokenAccountKey<T>()];
    assert!(token_account.pending.is_empty(), EPendingDepositsMustBeMerged);
    assert!(
        token_account
            .active
            .try_set_public_key(
                &token_account.pk,
                &new_pk,
                new_handles,
                rekey_proof,
                dst,
            ),
        EAmountsEqualityProofFailed,
    );
    token_account.pk = new_pk;
    token_account.verified_key_encryption = new_verified_key_encryption;
    events::emit_updated_public_key<T>(owner, new_pk, token_account.verified_key_encryption);
}

// === Transfer flows ===

/// Convert public coin to private tokens and add them to the public pending balance of `receiver`.
/// Authorized by `auth`, which must be for the `PERMISSIONED_WRAP` operation; `auth` may be for any owner.
public fun wrap<T>(
    receiver: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    deny_list: &DenyList,
    pool: &Pool<T>,
    coin: Coin<T>,
    memo: vector<u8>,
) {
    assert!(auth.is_allowed(PERMISSIONED_WRAP), EAuthorizationError);
    assert!(
        ct.is_active &&
        !is_frozen<T>(deny_list) &&
        !is_receiver_denied<T>(deny_list, receiver.owner),
        ETransferDenied,
    );
    let acc = &mut receiver[TokenAccountKey<T>()];
    assert!(!acc.is_frozen, ETransferDenied);
    assert!(acc.accepts_deposits, ETransferDenied);
    assert!(acc.public_balance.value() > 0
        || acc.has_deposit_slot(), EBalancesFull);

    let amount = coin.value();
    let public_coin = balance::wrap(coin, &pool.id);
    acc.public_balance.join(public_coin);

    events::emit_wrap<T>(receiver.owner, amount, memo);
}

/// Start a batched transfer from `sender`. `receiver_amounts[i]` is the transferred value
/// re-encrypted under `receiver_pks[i]`. `well_formed_proofs` is a single batched `WellFormedProof`
/// covering `receiver_amounts ++ [new_balance]` under `receiver_pks ++ [sender_pk]` — one aggregate
/// Bulletproof for the whole transfer. `total_sender_handle` is the single sender-keyed decryption handle
/// for the transfer total; `consistency_proof` proves it well-formed and `balance_proof` proves the
/// sender's balance drops by exactly that total (see `balance::try_split_batch`).
/// `seed_point` (= `P`) is forwarded to the events so the sender can re-derive each
/// transfer's blinding and recover its outgoing amounts; it is not otherwise verified on chain.
///
/// Returns `TransferBatch::Ok` when `balance_proof` verifies, else `BalanceProofFailed`. Aborts
/// if `well_formed_proofs` does not verify or `consistency_proof` fails. Call `add` once per
/// receiver, in `receiver_amounts` order, then `finalize`. Authorized by any `Auth<T>` for
/// `sender.owner`.
public fun batched_transfer<T>(
    sender: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    deny_list: &DenyList,
    mut receiver_pks: vector<Element<G>>,
    mut receiver_amounts: vector<EncryptedAmount>,
    well_formed_proofs: WellFormedProof,
    total_sender_handle: Element<G>,
    consistency_proof: ElGamalProof,
    seed_point: Element<G>,
    new_balance: EncryptedAmount,
    balance_proof: DdhProof,
): TransferBatch<T> {
    assert!(ct.is_active, ETransferDenied);
    assert!(auth.is_authenticated(sender.owner), EAuthorizationError);
    assert!(
        !is_sender_denied<T>(deny_list, sender.owner) && !is_frozen<T>(deny_list),
        ETransferDenied,
    );
    assert!(!receiver_amounts.is_empty(), EEmptyTransferBatch);
    assert!(receiver_amounts.length() <= MAX_BATCH_RECIPIENTS, EBatchTooLarge);
    assert!(receiver_amounts.length() == receiver_pks.length(), EEmptyTransferBatch);
    let sender_addr = sender.owner;
    let sender = &mut sender[TokenAccountKey<T>()];
    assert!(!sender.is_frozen, ETransferDenied);
    // `well_formed_proofs` is one aggregate proof over `[receiver_amounts..., new_balance]`
    // under `[receiver_pks..., sender.pk]`; verify and wrap into WFEAs in one call, then peel
    // the last entry off as the sender's new-balance WFEA.
    receiver_amounts.push_back(new_balance);
    receiver_pks.push_back(sender.pk);
    let mut wfeas = encrypted_amount::batch_into_well_formed(
        receiver_amounts,
        sender.session_id.dst(DST_ELGAMAL),
        sender.session_id.dst(DST_RANGE_PROOF_16),
        receiver_pks,
        well_formed_proofs,
    );
    let new_balance = wfeas.pop_back();
    let receiver_amounts = wfeas;
    let withdrawn = sender
        .active
        .try_split_batch(
            &sender.pk,
            new_balance,
            receiver_amounts,
            total_sender_handle,
            consistency_proof,
            sender.session_id.dst(DST_ELGAMAL),
            &balance_proof,
            sender.session_id.dst(DST_DDH),
        );

    if (withdrawn.is_some()) {
        let mut coins = withdrawn.destroy_some();
        // Reverse so `add_to_batch`'s `pop_back` consumes coins in submission order.
        coins.reverse();
        TransferBatch::Ok {
            sender: sender_addr,
            sender_pk: sender.pk,
            coins,
            seed_point,
            next_index: 0,
        }
    } else {
        withdrawn.destroy_none();
        TransferBatch::BalanceProofFailed
    }
}

/// Add a receiver to a batched transfer: pop the next receiver-keyed `EncryptedCoin` and credit it
/// to the receiver's pending deposits. Aborts if:
///  * the receiver is not registered, frozen, or on the deny list,
///  * `add_to_batch` is called more times than there were `receiver_amounts` in `batched_transfer`,
///  * the coin is not encrypted under the receiver's registered public key.
public fun add_to_batch<T>(
    batch: TransferBatch<T>,
    receiver: &mut Account,
    memo: vector<u8>,
    deny_list: &DenyList,
): TransferBatch<T> {
    match (batch) {
        // If batch is already failed, nothing should be mutated or emitted and the function should immediately return TransferBatch::BalanceProofFailed.
        TransferBatch::BalanceProofFailed => TransferBatch::BalanceProofFailed,
        // If batch is Ok, all mutations and checks must either succeed or assert, but never fail silently.
        TransferBatch::Ok {
            sender,
            sender_pk,
            mut coins,
            seed_point,
            next_index,
        } => {
            assert!(!coins.is_empty(), ETooManyReceivers);

            let receiver_addr = receiver.owner;
            assert!(!is_receiver_denied<T>(deny_list, receiver_addr), ETransferDenied);

            let coin = coins.pop_back();

            let receiver = &mut receiver[TokenAccountKey<T>()];
            assert!(!receiver.is_frozen, ETransferDenied);
            assert!(receiver.accepts_deposits, ETransferDenied);
            assert!(receiver.has_deposit_slot(), EBalancesFull);

            events::emit_transfer<T>(
                sender,
                sender_pk,
                seed_point,
                next_index,
                receiver_addr,
                receiver.pk,
                *coin.amount().amount(),
                memo,
            );
            receiver.pending.merge_encrypted(&receiver.pk, coin);
            TransferBatch::Ok {
                sender,
                sender_pk,
                coins,
                seed_point,
                next_index: next_index + 1,
            }
        },
    }
}

public use fun add_to_batch as TransferBatch.add;

/// Consume the `TransferBatch` to complete the transfer batch and return `true` if the transfer
/// succeeded and `false` if the balance proof failed.
public fun try_finalize<T>(batch: TransferBatch<T>): bool {
    match (batch) {
        TransferBatch::BalanceProofFailed => {
            // It is critical to make sure no events were emitted, or mutations were made before
            // this point.
            events::emit_try_transfer_failed();
            false
        },
        TransferBatch::Ok { coins, .. } => {
            assert!(coins.is_empty(), EAllAmountsMustBeUsed);
            coins.destroy_empty();
            true
        },
    }
}

/// Consume the `TransferBatch` to complete the transfer batch. Aborts if any check, including the
/// balance proof, failed.
public fun finalize<T>(batch: TransferBatch<T>) {
    assert!(batch.try_finalize(), EBalanceProofFailed);
}

/// Merge all pending deposits into the active balance.
/// This must be done before pending encrypted and public deposits can be used in a transfer.
/// To prevent overflows, the number of additions done with the active balance is limited,
/// including the number of additions done with the pending deposits.
/// Authorized by `auth`, which must be for `account.owner`. Any `Auth<T>` is accepted regardless
/// of which operation it covers.
public fun merge<T>(account: &mut Account, auth: &Auth<T>) {
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    let owner = account.owner;
    let acc = &mut account[TokenAccountKey<T>()];
    acc.active.merge_into(&mut acc.pending);
    acc.active.merge_public(acc.public_balance.take());
    events::emit_merge_deposits<T>(owner);
}

/// This may be used to update the balance after merging many pending deposits before
/// merging new deposits.
/// Authorized by `auth`, which must be for `account.owner`. Any `Auth<T>` is accepted regardless
/// of which operation it covers.
public fun update_active_balance<T>(
    account: &mut Account,
    auth: &Auth<T>,
    new_balance: EncryptedAmount,
    new_balance_proof: WellFormedProof,
    balance_proof: &DdhProof,
) {
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    let owner = account.owner;
    let token_account = &mut account[TokenAccountKey<T>()];
    let sid = token_account.session_id;
    assert!(
        token_account.try_update_active(new_balance, new_balance_proof, balance_proof, sid),
        EBalanceProofFailed,
    );
    events::emit_update_balance<T>(owner);
}

/// Re-state `self.active` as the well-formed `new_balance` (same key), proven equal in value by
/// `balance_proof`. Returns whether the proof verified; adds no authorization or event. Shared by
/// `update_active_balance` and the restate step of `try_set_public_key_and_unpause`.
fun try_update_active<T>(
    self: &mut TokenAccount<T>,
    new_balance: EncryptedAmount,
    new_balance_proof: WellFormedProof,
    balance_proof: &DdhProof,
    sid: vector<u8>,
): bool {
    let new_balance = new_balance.into_well_formed(
        sid.dst(DST_ELGAMAL),
        sid.dst(DST_RANGE_PROOF_16),
        self.pk,
        new_balance_proof,
    );
    self.active.try_update(&self.pk, new_balance, balance_proof, sid.dst(DST_DDH))
}

/// Take an amount of `Coin<T>` from the encrypted balance of `account`. Authorized by `auth`,
/// which must be for the `PERMISSIONED_UNWRAP` operation and for `account.owner`.
/// The caller needs to provide a proof that the new balance is correct after taking the amount:
/// - `new_balance` is the new encrypted balance of the account after taking the amount,
/// - `amount` is the amount of coins taken from the balance,
/// - `balance_proof` is a proof that `account.balance = new_balance + amount`.
public fun unwrap<T>(
    account: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    deny_list: &DenyList,
    pool: &mut Pool<T>,
    new_balance: EncryptedAmount,
    new_balance_proof: WellFormedProof,
    amount: u64,
    balance_proof: &DdhProof,
    ctx: &mut TxContext,
): Coin<T> {
    let (success, coin) = account.try_unwrap_internal(
        auth,
        ct,
        deny_list,
        pool,
        new_balance,
        new_balance_proof,
        amount,
        balance_proof,
        ctx,
    );
    assert!(success, EBalanceProofFailed);
    coin
}

/// Same as `unwrap` but does not abort if the balance proof fails. Instead, it emits a
/// `TryUnwrapFailedEvent` and returns a zero-value coin.
public fun try_unwrap<T>(
    account: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    deny_list: &DenyList,
    pool: &mut Pool<T>,
    new_balance: EncryptedAmount,
    new_balance_proof: WellFormedProof,
    amount: u64,
    balance_proof: &DdhProof,
    ctx: &mut TxContext,
): Coin<T> {
    let (success, coin) = account.try_unwrap_internal(
        auth,
        ct,
        deny_list,
        pool,
        new_balance,
        new_balance_proof,
        amount,
        balance_proof,
        ctx,
    );
    if (!success) {
        events::emit_try_unwrap_failed();
    };
    coin
}

/// Common unwrap logic shared by `unwrap` and `try_unwrap`.
/// Returns `(true, coin)` if the balance proof succeeds, or `(false, zero_coin)` if it fails.
fun try_unwrap_internal<T>(
    account: &mut Account,
    auth: &Auth<T>,
    ct: &ConfidentialToken<T>,
    deny_list: &DenyList,
    pool: &mut Pool<T>,
    new_balance: EncryptedAmount,
    new_balance_proof: WellFormedProof,
    amount: u64,
    balance_proof: &DdhProof,
    ctx: &mut TxContext,
): (bool, Coin<T>) {
    assert!(auth.is_allowed(PERMISSIONED_UNWRAP), EAuthorizationError);
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    assert!(ct.is_active, ETransferDenied);
    assert!(
        !is_frozen<T>(deny_list) && !is_sender_denied<T>(deny_list, account.owner),
        ETransferDenied,
    );
    let owner = account.owner;
    let account = &mut account[TokenAccountKey<T>()];
    assert!(!account.is_frozen, ETransferDenied);
    let sid = account.session_id;
    let new_balance = new_balance.into_well_formed(
        sid.dst(DST_ELGAMAL),
        sid.dst(DST_RANGE_PROOF_16),
        account.pk,
        new_balance_proof,
    );
    let withdrawn = account
        .active
        .try_split_to_public(
            &account.pk,
            new_balance,
            amount,
            balance_proof,
            sid.dst(DST_DDH),
        );
    if (withdrawn.is_some()) {
        let coin = withdrawn.destroy_some().unwrap(&mut pool.id, ctx);
        events::emit_unwrap<T>(owner, amount);
        (true, coin)
    } else {
        withdrawn.destroy_none();
        (false, coin::zero(ctx))
    }
}

public fun owner(account: &Account): address {
    account.owner
}

// === Admin ===

/// A function for the issuer to set the balance of an account directly.
/// This is used in cases where the issuer needs to intervene.
///
/// WARNING: This may break the consistency of the balance such that the number of confidential
/// tokens in circulation does not match the amount of coins in the pool. It is the responsibility
/// of the caller to ensure consistency is maintained when using this function.
/// The `upper_bound` is set to 1, so the caller is responsible for ensuring that the
/// `EncryptedAmount` is well-formed.
public fun set_balance_by_issuer<T>(
    t: &mut TreasuryCap<T>,
    account: &mut Account,
    new_balance: EncryptedAmount,
) {
    let owner = account.owner;
    let account = &mut account[TokenAccountKey<T>()];
    account.active.overwrite_unchecked(t, new_balance);
    account.pending.clear_unchecked(t);
    account.public_balance.set_zero_unchecked(t);
    events::emit_set_balance_by_issuer<T>(owner, new_balance);
}

/// Allow the given address to freeze the token globally or freeze individual accounts
/// (via the ManagementCap). Only the issuer can unfreeze (globally or per-account).
/// Aborts if the address already has the freeze capability.
public fun issue_freeze_cap<T>(
    ct: &mut ConfidentialToken<T>,
    _t: &ManagementCap<T>,
    addr: address,
) {
    ct.freeze_admins.insert(addr);
}

/// Revoke the freeze capability from the given address.
/// Aborts if the address does not have the freeze capability.
public fun revoke_freeze_cap<T>(
    ct: &mut ConfidentialToken<T>,
    _t: &ManagementCap<T>,
    addr: address,
) {
    ct.freeze_admins.remove(&addr);
}

/// Freeze the token globally. This prevents any transfers from happening until the token is
/// unfrozen again.
public fun global_freeze<T>(ct: &mut ConfidentialToken<T>, ctx: &mut TxContext) {
    assert!(ct.freeze_admins.contains(&ctx.sender()), EAuthorizationError);
    ct.is_active = false;
    events::emit_global_freeze<T>();
}

/// Unfreeze the token globally. This allows transfers to happen again and can only be done by the
/// token issuer.
public fun global_unfreeze<T>(ct: &mut ConfidentialToken<T>, _cap: &TreasuryCap<T>) {
    ct.is_active = true;
    events::emit_global_unfreeze<T>();
}

/// Freeze the given account for token `T`. A frozen account cannot transfer, receive, wrap,
/// or unwrap until unfrozen. Only addresses in `ct.freeze_admins` may call this.
public fun account_freeze<T>(ct: &ConfidentialToken<T>, account: &mut Account, ctx: &TxContext) {
    let admin = ctx.sender();
    assert!(ct.freeze_admins.contains(&admin), EAuthorizationError);
    let owner = account.owner;
    account[TokenAccountKey<T>()].is_frozen = true;
    events::emit_account_freeze<T>(admin, owner);
}

/// Unfreeze the given account for token `T`. Only the token issuer (holder of `&TreasuryCap<T>`)
/// may call this. The asymmetry — admins freeze, only the issuer unfreezes — mirrors
/// `global_freeze` / `global_unfreeze`.
public fun account_unfreeze<T>(_cap: &TreasuryCap<T>, account: &mut Account) {
    let owner = account.owner;
    account[TokenAccountKey<T>()].is_frozen = false;
    events::emit_account_unfreeze<T>(owner);
}

/// Set a policy for the confidential token.
/// This allows implementing permissioned operations, but only the witness type is stored here - the
/// logic must be handled in the corresponding flows.
/// See `register_permissioned` for an example of how this can be implemented.
/// Changing the witness type will break all in-flight permissioned calls using the old witness,
/// and thus highly discouraged.
public fun set_policy<T, W>(
    ct: &mut ConfidentialToken<T>,
    _t: &mut TreasuryCap<T>,
    permissioned_operations: vector<u8>,
) {
    policy::set<W>(&mut ct.policy, permissioned_operations);
    events::emit_policy_update<T, W>(permissioned_operations);
}

// === Auditor flows ===

/// Update the auditors for this confidential token by setting their new public keys in the
/// corresponding `auditors` struct. If `bump_recommended_min` is true, the auditors'
/// `recommended_min_version` is raised to the new version, signalling that all users should
/// call `set_public_key` with a valid viewing key encrypted towards the new auditor keys.
/// The floor is advisory; the chain does not enforce it on transfer.
/// The auditor flow can be disabled by inputting an empty `public_keys` vector.
public fun update_auditors<T>(
    ct: &mut ConfidentialToken<T>,
    _cap: &ManagementCap<T>,
    public_keys: vector<Element<G>>,
    bump_recommended_min: bool,
) {
    ct.auditors.update(public_keys, bump_recommended_min);
    events::emit_update_auditors<T>(
        *ct.auditors.pks(),
        ct.auditors.version(),
        ct.auditors.recommended_min_version(),
    );
}

// === Helpers ===

/// Return whether the given account has registered for the given token type.
fun has_token<T>(account: &Account): bool {
    df::exists(&account.id, TokenAccountKey<T>())
}

/// Slots available for new pending deposits. Always reserves one slot for a possible future
/// `merge_public` bump, so the cap compared against is `max_upper_bound() - 1` rather than
/// `max_upper_bound()`.
fun has_deposit_slot<T>(self: &TokenAccount<T>): bool {
    let cap = balance::max_upper_bound_minus_1();
    let used = self.active.upper_bound() + self.pending.upper_bound();
    cap > used
}

/// 20-byte session_id for `account`'s `TokenAccount<T>`.
public(package) fun session_id<T>(account: &Account): vector<u8> {
    // TODO: Switch to a simple hash of the account ID and token type.
    // TODO: Must be unique across different chains.
    derived_object::derive_address(account.id.to_inner(), TokenAccountKey<T>()).to_bytes().take(20)
}

/// 21-byte Fiat-Shamir DST `session_id || protocol_id`.
public(package) fun dst(session_id: vector<u8>, protocol_id: u8): vector<u8> {
    let mut bytes = session_id;
    bytes.push_back(protocol_id);
    bytes
}

use fun dst as vector.dst;

// === Syntactic Sugar ===

#[syntax(index)]
fun borrow<T>(acc: &Account, key: TokenAccountKey<T>): &TokenAccount<T> {
    df::borrow(&acc.id, key)
}

#[syntax(index)]
fun borrow_mut<T>(acc: &mut Account, key: TokenAccountKey<T>): &mut TokenAccount<T> {
    df::borrow_mut(&mut acc.id, key)
}

// === Test Helpers ===

#[test_only]
use contra::twisted_elgamal::Encryption;

#[test_only]
public fun protocol_id_ddh(): u8 { DST_DDH }

#[test_only]
public fun protocol_id_elgamal(): u8 { DST_ELGAMAL }

#[test_only]
public fun protocol_id_key_consistency(): u8 { DST_KEY_CONSISTENCY }

#[test_only]
public fun protocol_id_range_proof_16(): u8 { DST_RANGE_PROOF_16 }

#[test_only]
public fun protocol_id_range_proof_32(): u8 { DST_RANGE_PROOF_32 }

#[test_only]
public fun protocol_id_batch_ddh(): u8 { DST_BATCH_DDH }

#[test_only]
public fun new_account_registry_for_testing(ctx: &mut TxContext): AccountRegistry {
    AccountRegistry { id: object::new(ctx) }
}

#[test_only]
public fun new_token_registry_for_testing(ctx: &mut TxContext): TokenRegistry {
    TokenRegistry { id: object::new(ctx) }
}

#[test_only]
public fun balance<T>(account: &Account): Encryption {
    account[TokenAccountKey<T>()].active.collapse()
}

#[test_only]
public fun pending_encrypted_balance<T>(account: &Account): Encryption {
    account[TokenAccountKey<T>()].pending.collapse()
}

#[test_only]
public fun verified_key_encryption_version<T>(account: &Account): u32 {
    account[TokenAccountKey<T>()].verified_key_encryption.key_version()
}

#[test_only]
public fun verified_key_encryption_is_set<T>(account: &Account): bool {
    account[TokenAccountKey<T>()].verified_key_encryption.is_set()
}

#[test_only]
public fun account_is_frozen<T>(account: &Account): bool {
    account[TokenAccountKey<T>()].is_frozen
}

#[test_only]
public fun accepts_deposits<T>(account: &Account): bool {
    account[TokenAccountKey<T>()].accepts_deposits
}

/// Test-only equivalent of `Auditors::verify_key_encryption` that skips the Bulletproof range
/// check inside the `KeyConsistencyProof`. Move tests cannot generate real Bulletproof bytes, so
/// they assert each limb is a u32 out of band and only verify the sigma protocol on-chain. Pair
/// with `register_internal` / `set_public_key_internal` to bypass range checks in tests.
#[test_only]
public fun verify_key_encryption_for_testing<T>(
    ct: &ConfidentialToken<T>,
    pk: &Element<G>,
    key_encryption: Option<KeyEncryption>,
    dst: vector<u8>,
): VerifiedKeyEncryption {
    ct.auditors.verify_key_encryption_for_testing(pk, key_encryption, dst)
}

#[test_only]
public fun derive_dst_for_testing<T>(account: &Account, protocol_id: u8): vector<u8> {
    account.session_id<T>().dst(protocol_id)
}
