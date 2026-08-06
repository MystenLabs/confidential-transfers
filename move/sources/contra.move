// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Confidential transfers on Sui.
///
/// Enables token transfers where amounts are encrypted using twisted ElGamal
/// encryption while remaining verifiable through zero-knowledge proofs.
///
/// ## Key Flows for the Token Issuer of public token type `T`:
/// 1. Create a new confidential token for a token type `T` (using the TreasuryCap), optionally
///    with an initial auditor public key. Creation returns a `ManagementCap<T>`.
/// 2. Set the freeze admins who can freeze the token globally or specific accounts (via the
///    ManagementCap). Those admins may monitor the confidential token and freeze it or
///    individual accounts if necessary.
/// 3. Unfreeze the token globally or a specific account (using the TreasuryCap).
/// 4. Set the balance of an account directly, to emulate burn/seize (using the TreasuryCap).
/// 5. Freeze specific accounts via the token's deny list, using
///    `sui::coin::deny_list_v2_add` / `sui::coin::deny_list_v2_remove`. The deny list affects
///    both the public and the private coin; to freeze only the private coin, see items 2 and 3.
/// 6. Rotate or disable the auditor key via `update_auditor` (using the ManagementCap). The
///    outgoing key stays valid for transfers through a caller-set `expiration_epoch` (a grace
///    window for in-flight transfers). Passing `none` disables auditing going forward. Auditing is
///    per-transfer and each transfer carries auditor-readable ciphertexts of the amount, so the auditor
///    never learns users' viewing keys.
/// 7. [Advanced] Set the policy for the confidential token (using the TreasuryCap). Policies define
///    which operations are permissioned. Currently supported permissioned operations are:
///    - `register`: Register a token account for a token type `T`. E.g., caller ensures the user is
///      KYCed before registering an account. When set, setting the public key for an account
///      is also permissioned.
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
/// 1. Create an account for an address (permissionless, needed once for all token types). Optionally
///    set a default key later (`set_default_pk_as_sender`) so others can auto-register tokens for you
///    via `register_with_default_pk`.
/// 2. Register a token account for a token type `T` under a key of your choice (`register`). Per-token
///    keys are independent of the account's default key.
/// 3. Rotate a token's key with `rekey_token_account` (to any `new_pk`), and set/clear the account's default
///    key with `set_default_pk_as_sender`.
/// 4. Wrap a public coin into a confidential token, adding to the pending encrypted balance of an
///    account.
/// 5. Transfer an encrypted amount to one or more token accounts. Every receiver must already have a
///    `TokenAccount<T>`; for permissionless tokens anyone can create one on their behalf up front
///    with `register_with_default_pk`. Auditor data is attached if set.
/// 6. Unwrap an encrypted amount from a token account and convert it to public coins.
///
/// ## Authentication:
/// Some functions require authorization via an `Auth<T>` argument. Under the default
/// permissionless policy any `Auth<T>` is accepted. Permissioning narrows which constructors
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
    auditors::{Auditor, AuditorPackage, new as new_auditor},
    balance::{Self, EncryptedBalance, EncryptedCoin, PublicCoin},
    deny_list::{is_frozen, is_receiver_denied, is_sender_denied},
    encrypted_amount::{
        Self,
        EncryptedAmount,
        DecryptionHandles,
        WellFormedEncryptedAmount,
        WellFormedProof,
    },
    events,
    nizk::{DdhProof, ElGamalProof},
    policy::{Self, Auth, Policy},
    twisted_elgamal::{PublicKey, public_key}
};
use sui::{
    coin::{Self, Coin, TreasuryCap},
    deny_list::DenyList,
    derived_object,
    dynamic_field as df,
    group_ops::Element,
    ristretto255::G,
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
const EBalancesFull: u64 = 10;
const EBatchTooLarge: u64 = 12;
const EReceiverNotRegistered: u64 = 16;
const ERegistrationNotPermissionless: u64 = 17;
const EDefaultPkNotSet: u64 = 18;

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
const DST_RANGE_PROOF_16: u8 = 0x04;
const DST_BATCH_DDH: u8 = 0x06;
const DST_AUDITOR_ELGAMAL: u8 = 0x07;

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
    auditor: Auditor,
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
    default_pk: Option<PublicKey>,
}

/// A user's account for one confidential token.
public struct TokenAccount<phantom T> has store {
    pk: PublicKey,
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
        sender_pk: PublicKey,
        coins: vector<EncryptedCoin<T>>,
        seed_point: Element<G>,
        next_index: u8,
        auditor_decryption_handles: vector<DecryptionHandles>,
        auditor_pk: Option<PublicKey>,
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
/// Sets the token's auditor key to `auditor_pk` (per-transfer auditing). Pass `none` to start with
/// auditing disabled. The issuer can enable or rotate it later via `update_auditor`.
///
/// Returns the created `ConfidentialToken` and a `ManagementCap` that can be used to perform
/// administrative operations for this token.
public fun new_confidential_token<T>(
    registry: &mut TokenRegistry,
    _t: &mut TreasuryCap<T>,
    auditor_pk: Option<PublicKey>,
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
            auditor: new_auditor(auditor_pk),
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

/// Create a new account owned by `owner`, with no default key set (set one later with
/// `set_default_pk_as_sender` / `set_default_pk_as_object`). Permissionless: anyone can create the
/// account for any owner — it only reserves the owner's derived slot and sets no key. Aborts if
/// `owner` already has an account.
public fun new_account(registry: &mut AccountRegistry, owner: address): Account {
    assert!(!derived_object::exists(&registry.id, AccountKey(owner)), EAccountAlreadyRegistered);
    let id = derived_object::claim(&mut registry.id, AccountKey(owner));
    Account { id, owner, default_pk: option::none() }
}

/// Share the account object.
/// This has do be done after `new_account`, but it allows the user to create token
/// accounts for confidential tokens immediately.
public fun share_account(account: Account) {
    transfer::share_object(account);
}

/// Create a `TokenAccount` for token `T`, with its balances keyed under `pk`. Authorized by `auth`,
/// which must be for the `PERMISSIONED_REGISTER` operation and for `account.owner`.
public fun register<T>(account: &mut Account, auth: &Auth<T>, pk: PublicKey) {
    assert!(auth.is_allowed(PERMISSIONED_REGISTER), EAuthorizationError);
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    let session_id = account.session_id<T>();
    account.add_token_account<T>(pk, session_id);
}

/// Permissionless `register`: create a `TokenAccount<T>` keyed under the account's `default_pk`,
/// without any `Auth`. Requires `T`'s registration permissionless and `default_pk` set.
public fun register_with_default_pk<T>(account: &mut Account, ct: &ConfidentialToken<T>) {
    assert!(account.default_pk.is_some(), EDefaultPkNotSet);
    assert!(
        policy::is_permissionless(&ct.policy, PERMISSIONED_REGISTER),
        ERegistrationNotPermissionless,
    );
    let pk = *account.default_pk.borrow();
    let session_id = account.session_id<T>();
    account.add_token_account<T>(pk, session_id);
}

/// Create a `TokenAccount<T>` on `account`, keyed under `pk`. Aborts if the token is already
/// registered. The caller is responsible for any authorization.
fun add_token_account<T>(account: &mut Account, pk: PublicKey, session_id: vector<u8>) {
    assert!(!account.has_token<T>(), EAccountAlreadyRegistered);
    events::emit_new_registration<T>(account.owner, pk);
    df::add(
        &mut account.id,
        TokenAccountKey<T>(),
        TokenAccount<T> {
            pk,
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

/// Set the account's optional `default_pk` (pass `none` to clear it, which disables permissionless
/// auto-registration).
public fun set_default_pk_as_sender(
    account: &mut Account,
    default_pk: Option<PublicKey>,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == account.owner, EAuthorizationError);
    account.set_default_pk_internal(default_pk);
}

/// Set the `default_pk` of an account owned by the object identified by `uid`. Holding `&mut UID`
/// proves custody of the object, so it self-authenticates as its own owner.
#[allow(unused_mut_parameter)]
public fun set_default_pk_as_object(
    account: &mut Account,
    default_pk: Option<PublicKey>,
    uid: &mut UID,
) {
    assert!(uid.to_inner().to_address() == account.owner, EAuthorizationError);
    account.set_default_pk_internal(default_pk);
}

fun set_default_pk_internal(account: &mut Account, default_pk: Option<PublicKey>) {
    account.default_pk = default_pk;
    events::emit_default_pk_rotated(account.owner, default_pk);
}

/// Re-key token `T`'s active balance from its current `TokenAccount.pk` to `new_pk`, swapping each
/// limb's decryption handle for the matching `new_handles[i]` (proven by `rekey_proof`). `new_pk` is
/// explicit and independent of the account's default key. Aborts if the token has unmerged pending
/// deposits (which are under the old key, so they must be merged first) or the proof fails.
/// Authorized by `auth`, which must be for the `PERMISSIONED_REGISTER` operation and for
/// `account.owner`.
public fun rekey_token_account<T>(
    account: &mut Account,
    auth: &Auth<T>,
    new_pk: PublicKey,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
) {
    assert!(auth.is_allowed(PERMISSIONED_REGISTER), EAuthorizationError);
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    assert!(
        rekey_token_account_internal<T>(account, new_pk, new_handles, rekey_proof),
        EAmountsEqualityProofFailed,
    );
}

/// Like `rekey_token_account` but soft-fails instead of aborting if the re-key proof does not verify
/// (e.g. a deposit raced the caller's read). The re-key flow pauses the token first (`accepts_deposits
/// = false`) so no deposit lands under the old key mid-rotation; on success this re-keys the token and
/// resumes deposits (`accepts_deposits = true`), now under the new key. On failure it emits
/// `TryTokenRekeyFailedEvent` and leaves the token unchanged (still paused) for a retry. Still aborts
/// on unmerged pending deposits.
public fun try_rekey_token_account<T>(
    account: &mut Account,
    auth: &Auth<T>,
    new_pk: PublicKey,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
) {
    assert!(auth.is_allowed(PERMISSIONED_REGISTER), EAuthorizationError);
    assert!(auth.is_authenticated(account.owner), EAuthorizationError);
    let owner = account.owner;
    if (rekey_token_account_internal<T>(account, new_pk, new_handles, rekey_proof)) {
        account[TokenAccountKey<T>()].accepts_deposits = true;
    } else {
        events::emit_try_token_rekey_failed<T>(owner);
    };
}

/// Shared re-key: Assert the token's pending is empty, then re-key its active balance from
/// `TokenAccount.pk` to `new_pk`. On a verifying proof, commits the new handles,
/// sets `token.pk = new_pk`, emits `TokenRekeyedEvent`, and returns `true`. Otherwise leaves the token
/// unchanged and returns `false`.
fun rekey_token_account_internal<T>(
    account: &mut Account,
    new_pk: PublicKey,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
): bool {
    let owner = account.owner;
    let token_account = &mut account[TokenAccountKey<T>()];
    assert!(token_account.pending.is_empty(), EPendingDepositsMustBeMerged);
    let dst = token_account.session_id.dst(DST_BATCH_DDH);
    if (
        token_account
            .active
            .try_set_public_key(&token_account.pk, &new_pk, new_handles, rekey_proof, dst)
    ) {
        token_account.pk = new_pk;
        events::emit_token_rekeyed<T>(owner, new_pk);
        true
    } else {
        false
    }
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
    assert!(receiver.has_token<T>(), EReceiverNotRegistered);
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
/// Per-transfer auditing: when `ct`'s auditor key is enabled, `auditor_package` must be `some`.
/// See `auditors::verify_transfer` for details.
///
/// Returns `TransferBatch::Ok` when `balance_proof` verifies, else `BalanceProofFailed`. Aborts
/// if `well_formed_proofs`, the auditor requirement, or `consistency_proof` fails. Call `add` once
/// per receiver, in `receiver_amounts` order, then `finalize`. Authorized by any `Auth<T>` for
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
    auditor_package: Option<AuditorPackage>,
    ctx: &TxContext,
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
    let mut receiver_pks = receiver_pks.map!(|pk| public_key(pk));
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

    let (mut auditor_decryption_handles, auditor_pk) = ct
        .auditor
        .verify_transfer(
            &receiver_amounts,
            auditor_package,
            ctx.epoch(),
            sender.session_id.dst(DST_AUDITOR_ELGAMAL),
        );

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
        // Reverse coins and auditor handles so `add_to_batch`'s `pop_back` consumes them in
        // submission order.
        coins.reverse();
        auditor_decryption_handles.reverse();
        TransferBatch::Ok {
            sender: sender_addr,
            sender_pk: sender.pk,
            coins,
            seed_point,
            next_index: 0,
            auditor_decryption_handles,
            auditor_pk,
        }
    } else {
        withdrawn.destroy_none();
        TransferBatch::BalanceProofFailed
    }
}

/// Add a receiver to a batched transfer: pop the next receiver-keyed `EncryptedCoin` and credit it
/// to the receiver's pending deposits. The receiver must already have a `TokenAccount<T>` (for
/// permissionless tokens anyone can create one up front with `register_with_default_pk`). Aborts if:
///  * the receiver has no `TokenAccount<T>`,
///  * the receiver is frozen or on the deny list,
///  * `add_to_batch` is called more times than there were `receiver_amounts` in `batched_transfer`,
///  * the coin is not encrypted under the receiver's public key.
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
            mut auditor_decryption_handles,
            auditor_pk,
        } => {
            assert!(!coins.is_empty(), ETooManyReceivers);

            let receiver_addr = receiver.owner;
            assert!(!is_receiver_denied<T>(deny_list, receiver_addr), ETransferDenied);
            assert!(receiver.has_token<T>(), EReceiverNotRegistered);

            let coin = coins.pop_back();

            let receiver_auditor_decryption_handles = if (auditor_decryption_handles.is_empty()) {
                option::none()
            } else {
                option::some(auditor_decryption_handles.pop_back())
            };

            let receiver = &mut receiver[TokenAccountKey<T>()];
            assert!(!receiver.is_frozen, ETransferDenied);
            assert!(receiver.accepts_deposits, ETransferDenied);
            assert!(receiver.has_deposit_slot(), EBalancesFull);
            let receiver_pk = receiver.pk;

            events::emit_transfer<T>(
                sender,
                sender_pk,
                seed_point,
                next_index,
                receiver_addr,
                receiver_pk,
                *coin.amount().amount(),
                receiver_auditor_decryption_handles,
                auditor_pk,
                memo,
            );
            receiver.pending.merge_encrypted(&receiver_pk, coin);
            TransferBatch::Ok {
                sender,
                sender_pk,
                coins,
                seed_point,
                next_index: next_index + 1,
                auditor_decryption_handles,
                auditor_pk,
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
        TransferBatch::Ok { coins, auditor_decryption_handles, .. } => {
            assert!(
                coins.is_empty() && auditor_decryption_handles.is_empty(),
                EAllAmountsMustBeUsed,
            );
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

/// Re-state `self.active` as the well-formed `new_balance` (same key `self.pk`), proven equal in
/// value by `balance_proof`. Returns whether the proof verified; adds no authorization or event.
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

/// Rotate this confidential token's auditor key to `new_pk` (pass `none` to disable auditing). The
/// outgoing key stays valid for transfers through `expiration_epoch`, so transfers built against it
/// just before the rotation still verify (see `auditors::verify_transfer`).
public fun update_auditor<T>(
    ct: &mut ConfidentialToken<T>,
    _cap: &ManagementCap<T>,
    new_pk: Option<PublicKey>,
    expiration_epoch: u64,
) {
    let previous_pk = ct.auditor.update(new_pk, expiration_epoch);
    events::emit_update_auditors<T>(new_pk, previous_pk, expiration_epoch);
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
    let cap = balance::max_upper_bound() - 1;
    let used = self.active.upper_bound() + self.pending.upper_bound();
    cap > used
}

/// 20-byte session_id for `account`'s `TokenAccount<T>`.
fun session_id<T>(account: &Account): vector<u8> {
    // `derive_address` hashes the account ID together with the full `TokenAccountKey<T>` type
    // tag. The account ID is itself derived from the `AccountRegistry`, which is unique per
    // standalone deployment of contra.
    // TODO: Once contra is added to the framework, verify session ids stay chain-unique.
    derived_object::derive_address(account.id.to_inner(), TokenAccountKey<T>()).to_bytes().take(20)
}

/// 21-byte Fiat-Shamir DST `session_id || protocol_id`.
fun dst(session_id: vector<u8>, protocol_id: u8): vector<u8> {
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
public fun protocol_id_batch_ddh(): u8 { DST_BATCH_DDH }

#[test_only]
public fun protocol_id_auditor_elgamal(): u8 { DST_AUDITOR_ELGAMAL }

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
public fun account_is_frozen<T>(account: &Account): bool {
    account[TokenAccountKey<T>()].is_frozen
}

#[test_only]
public fun accepts_deposits<T>(account: &Account): bool {
    account[TokenAccountKey<T>()].accepts_deposits
}

/// The account's optional default key (`none` if unset), as a raw group element. Off-chain readers
/// decode the `default_pk` field straight from the account object rather than calling this.
#[test_only]
public fun default_pk(account: &Account): Option<Element<G>> {
    account.default_pk.map!(|pk| *pk.as_element())
}

#[test_only]
public fun token_public_key<T>(account: &Account): Element<G> {
    *account[TokenAccountKey<T>()].pk.as_element()
}

#[test_only]
public fun derive_dst_for_testing<T>(account: &Account, protocol_id: u8): vector<u8> {
    account.session_id<T>().dst(protocol_id)
}
