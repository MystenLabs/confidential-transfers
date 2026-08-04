// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Payment channels on top of `contra` confidential tokens.
///
/// A `Channel<T>` is a shared object that owns a confidential `Account` (via
/// `contra::authorize_as_object` auth derived from the channel's UID). The funder, called
/// the "sender", deposits funds into the channel's account once and then signs
/// off-chain a sequence of single-receiver transfers paying out increasing
/// amounts to a fixed receiver chosen at `activate` time. Each off-chain
/// transfer is a Sui transaction whose `Channel` move call is signed by the
/// sender; the receiver chooses which (latest) transfer to broadcast and pays
/// gas as the *sponsor*, completing the second signature required by Sui
/// sponsored transactions.
///
/// The module exposes only one privileged operation, `get_auth`, which
/// dispenses an `Auth<T>` over the channel's contra account under the rules
/// below. Every actual contra operation — including creating and registering
/// the channel's `TokenAccount<T>` — is then a plain `contra` move call with
/// that auth, composed by the caller in the same PTB.
///
/// # State machine
/// - `Initialized` — fresh channel; the sender has full control via
///   `get_auth` and uses it to set up the channel's contra account
///   (`contra::new_account` keyed by `address_of(channel)` then
///   `contra::register` with the channel's auth), fund it, etc.
/// - `Active { receiver, end_time_ms }` — sender called `activate`, locking
///   themselves out: `get_auth` only returns an auth if the call is
///   receiver-sponsored (`ctx.sponsor() == Some(receiver)`) or after the
///   timeout (`clock.timestamp_ms() >= end_time_ms`). Either case
///   transitions state to `Closed`.
/// - `Closed` — `get_auth` is again unconditionally available so the sender
///   can sweep the residual.
///
/// # Settlement flow
/// To pay the receiver `X`, the sender builds a PTB consisting of:
///   1. `payment_channel::get_auth(channel, ct, clock, ctx)` → `Auth<T>`,
///   2. `contra::batched_transfer(channel_account, ct, [amount(X)],
///      new_balance, balance_proof, deny_list, auth)`,
///   3. `contra::add_to_batch(batch, receiver_account, none, deny_list)`,
///   4. `contra::finalize(batch)`,
/// signs as `ctx.sender = c.sender` (with the channel still `Active`), and
/// hands the unsigned bytes + sender signature to the receiver. The receiver
/// dry-runs to verify the encrypted amount paid to them, signs as gas
/// sponsor, and broadcasts. On chain, step 1 sees `ctx.sponsor() ==
/// Some(receiver)` while `Active`, returns the auth, and atomically flips
/// state to `Closed`; if the contra balance proof in step 4 fails, the entire
/// PTB aborts and the state change in step 1 is rolled back.
///
/// # Privacy
/// All transfer amounts and account balances appear on chain only as
/// twisted-ElGamal ciphertexts under the channel's public key, so to any
/// third-party observer (or any other channel participant) every amount —
/// the locked balance, the per-settlement payment, the sender's residual —
/// is hidden by contra's confidentiality.
///
/// The channel preserves that confidentiality even *from the receiver*: the
/// receiver only learns the per-transfer amount they decrypt with their own
/// secret key. They do not learn the channel's locked balance, the sender's
/// remaining balance after a transfer, or any earlier off-chain transfer the
/// receiver chose not to broadcast.
///
/// # Receiver acceptance checks
/// Before the receiver agrees to *use* a channel offered by a sender, they
/// fetch the on-chain `Channel<T>` object and verify off chain:
///   - the type parameter `T` is the token they expected to be paid in;
///   - `state` is `Active` (channel was funded and locked, so `get_auth`
///     can only release auth on receiver-sponsored settlement or timeout);
///   - inside `Active { receiver, end_time_ms }`: `receiver` matches their
///     own address and `end_time_ms` is far enough in the future to give
///     them comfortable time to settle.
/// They do NOT need to verify the channel's balance — every settlement PTB
/// is dry-run before the receiver signs as gas sponsor, so an underfunded
/// or otherwise invalid transfer would fail in dry-run and be rejected.
///
/// On every settlement, the receiver dry-runs the sender-signed PTB and
/// inspects the contra `TransferEvent` it would emit:
///   - `sender` equals the channel's contra-account address
///     (`address_of(channel)`) — proves the funds come from *this* channel,
///     not someone else's;
///   - `receiver` equals the receiver's own contra-account address —
///     proves the funds are being paid to *them*, not to a third party;
///   - decrypting `encrypted_amount_receiver` with the receiver's
///     viewing key yields the cumulative amount the sender promised off
///     chain.
/// Any mismatch means the PTB is not the settlement the sender claimed,
/// and the receiver MUST NOT sign as gas sponsor.
///
/// # Lifecycle
/// 1. `new` — create and share the `Channel<T>`. State = `Initialized`.
/// 2. Sender calls `get_auth` and uses the returned `Auth<T>` to:
///    a. Create the channel's contra account via
///       `contra::new_account(registry, address_of(channel))`,
///    b. `contra::register` it with the channel's `pk` (passing the auth
///       through `contraClient.register({ ..., auth })`),
///    c. Fund it (`contra::wrap` then `contra::merge` with the same auth).
/// 3. `activate` — sender locks the channel by naming `receiver` and
///    `end_time_ms`; state = `Active { receiver, end_time_ms }`.
/// 4. Receiver-sponsored settlement PTB (see "Settlement flow" above) — auth
///    is released and state transitions to `Closed`. Or, if the receiver
///    vanishes, the sender calls `get_auth` after `end_time_ms`; that call
///    flips state to `Closed` and returns the auth.
/// 5. From `Closed`, the sender uses `get_auth` to sweep / withdraw.
module payment_channel::payment_channel;

use contra::{contra::{Self, Account, AccountRegistry, ConfidentialToken}, policy::Auth};
use sui::{clock::Clock, group_ops::Element, ristretto255::G};

// === Errors ===

const EUnauthorized: u64 = 0;
const ENotInitialized: u64 = 1;
const EChannelActive: u64 = 2;

// === Types ===

public enum State has copy, drop, store {
    Initialized,
    Active { receiver: address, end_time_ms: u64 },
    Closed,
}

public struct Channel<phantom T> has key {
    id: UID,
    sender: address,
    state: State,
}

// === Construction ===

/// Create and share an empty `Channel<T>`. The channel's `sender` is set to
/// `ctx.sender()` and state starts as `Initialized`. The contra account that
/// will back the channel is *not* created here — the sender creates it via
/// `new_account` (object-bound) and registers it via `get_auth` +
/// `contra::register` (passing the channel auth).
public fun new<T>(ctx: &mut TxContext) {
    let c = Channel<T> {
        id: object::new(ctx),
        sender: ctx.sender(),
        state: State::Initialized,
    };
    transfer::share_object(c);
}

/// Create the contra `Account` owned by the channel's address, with account key `pk`. Restricted to
/// the channel `sender`, and object-bound (the channel self-authenticates via its own `&mut UID`), so
/// no one else can squat the channel's account with a key they control.
public fun new_account<T>(
    c: &mut Channel<T>,
    registry: &mut AccountRegistry,
    pk: Element<G>,
    ctx: &TxContext,
): Account {
    assert!(ctx.sender() == c.sender, EUnauthorized);
    contra::new_account_for_object(registry, &mut c.id, pk)
}

// === Operations ===

/// Hand the sender an `Auth<T>` over the channel's contra account.
///
/// Always requires `ctx.sender() == c.sender`. Then:
/// - If state is `Initialized` or `Closed`, returns the auth unconditionally.
/// - If state is `Active { receiver, end_time_ms }`, returns the auth iff
///   `ctx.sponsor() == Some(receiver)` (receiver-sponsored settlement) or
///   `clock.timestamp_ms() >= end_time_ms` (timeout bypass). In either case,
///   the call also flips state to `Closed` so subsequent calls take the
///   unconditional `Closed` path.
public fun get_auth<T>(
    c: &mut Channel<T>,
    ct: &ConfidentialToken<T>,
    clock: &Clock,
    ctx: &TxContext,
): Auth<T> {
    assert!(ctx.sender() == c.sender, EUnauthorized);
    let close_active = match (&c.state) {
        State::Active {
            receiver,
            end_time_ms,
        } => clock.timestamp_ms() >= *end_time_ms || ctx.sponsor().contains(receiver),
        _ => false,
    };
    if (close_active) {
        c.state = State::Closed;
    };
    assert!(!c.state.is_active(), EChannelActive);
    contra::authorize_as_object(ct, &mut c.id)
}

/// Sender locks the channel by naming the receiver and the end-time deadline:
/// state goes `Initialized → Active { receiver, end_time_ms }`. After this,
/// `get_auth` will only release auth on receiver-sponsorship or timeout.
public fun activate<T>(c: &mut Channel<T>, receiver: address, end_time_ms: u64, ctx: &TxContext) {
    assert!(ctx.sender() == c.sender, EUnauthorized);
    assert!(c.state.is_initialized(), ENotInitialized);
    c.state = State::Active { receiver, end_time_ms };
}

// === Accessors ===

public fun sender<T>(c: &Channel<T>): address { c.sender }

public fun state<T>(c: &Channel<T>): State { c.state }

/// Address that owns the channel's `contra::Account` — pass this to
/// `contra::new_account(registry, address_of(channel))` when setting up the
/// channel's contra account in the same PTB as `get_auth`.
public fun address_of<T>(c: &Channel<T>): address {
    object::id_address(c)
}

/// `Some(receiver)` iff the channel is currently `Active`.
public fun receiver<T>(c: &Channel<T>): Option<address> {
    match (&c.state) {
        State::Active { receiver, .. } => option::some(*receiver),
        _ => option::none(),
    }
}

/// `Some(end_time_ms)` iff the channel is currently `Active`.
public fun end_time_ms<T>(c: &Channel<T>): Option<u64> {
    match (&c.state) {
        State::Active { end_time_ms, .. } => option::some(*end_time_ms),
        _ => option::none(),
    }
}

public fun is_initialized(s: &State): bool {
    match (s) {
        State::Initialized => true,
        _ => false,
    }
}

public fun is_active(s: &State): bool {
    match (s) {
        State::Active { .. } => true,
        _ => false,
    }
}

public fun is_closed(s: &State): bool {
    match (s) {
        State::Closed => true,
        _ => false,
    }
}
