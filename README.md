# Confidential Transfers on Sui

> **Disclaimer:** The code in this repository is still a work in progress and is not final. It has not been audited and should not be used in production.

Confidential token transfers on the [Sui](https://sui.io) blockchain. Balances and transfer amounts stay hidden using **Twisted ElGamal** homomorphic encryption and **zero-knowledge proofs**, while the network still validates that every transaction is correct.

- **Privacy** -- token balances and transfer amounts are encrypted on-chain; only the account holder can decrypt them.
- **Correctness without trust** -- zero-knowledge proofs guarantee that encrypted operations are valid (no overdrafts, no inflation) without revealing the underlying values.
- **Composability** -- any Sui `Coin<T>` can be wrapped into a confidential token and unwrapped back, so the system layers on top of existing token standards.
- **Compliance ready** -- issuers can attach auditor keys so designated parties can decrypt balances and transfers for oversight, and retain freeze and seize controls to pause accounts or recover funds when required. Also, an account holder can produce a zero-knowledge proof of their balance, or of the amount of a transfer they sent or received, convincing any verifier holding their public key without exposing the private key.

> **Privacy boundary:** privacy holds for activity *inside* the confidential domain — transfers between registered accounts hide the amount, leaving only sender, receiver, and timing visible. Crossing the boundary into or out of the domain — wrapping a public `Coin<T>` in, or unwrapping back to a public `Coin<T>` — touches the public coin layer and therefore reveals the amount and counterparties of that single operation, like any other Sui coin transaction.

### Basic flows at a glance

Yellow nodes live in the public domain (amounts visible on-chain), blue nodes live in the confidential domain (amounts encrypted).

**1. Register** — one-time setup per `(user, token T)` pair. Alice publishes a public key `pk` and (if the token has auditors) her key encrypted to the current auditor set, creating her `TokenAccount<T>`.

```mermaid
flowchart LR
    Alice(["Alice"]):::pub
    TA["Alice's<br/>TokenAccount&lt;T&gt;<br/>pk"]:::conf

    Alice ==>|"register&lt;T&gt;"| TA

    classDef pub fill:#fef9c3,stroke:#a16207,color:#713f12;
    classDef conf fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;
```

**2. Wrap** — moves value from the public coin layer into Bob's (or Alice's) confidential account. The amount is visible (it's a public `Coin<T>` deposit); the coin reserve is held in `Pool<T>`, and Bob's pending public balance is credited.

```mermaid
flowchart LR
    Coin["Alice's<br/>Coin&lt;T&gt;"]:::pub
    Pool[("Pool&lt;T&gt;<br/>reserve")]:::pub
    TA["Bob's<br/>TokenAccount&lt;T&gt;<br/>pending public ↑"]:::conf

    Coin ==>|"wrap (amount)"| TA
    Coin -.->|"deposit"| Pool

    classDef pub fill:#fef9c3,stroke:#a16207,color:#713f12;
    classDef conf fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;
```

**3. Transfer** — confidential-to-confidential. Alice's active balance is debited and Bob's pending encrypted balance is credited; the amount, encrypted under both keys, never leaves the confidential domain.

```mermaid
flowchart LR
    Sender["Alice's<br/>TokenAccount&lt;T&gt;<br/>active ↓"]:::conf
    Receiver["Bob's<br/>TokenAccount&lt;T&gt;<br/>pending encrypted ↑"]:::conf

    Sender ==>|"transfer (encrypted amount)"| Receiver

    classDef conf fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;
```

**4. Unwrap** — moves value back out to the public coin layer. Alice's active balance is debited and a public `Coin<T>` of the chosen amount is paid out from `Pool<T>` to the recipient.

```mermaid
flowchart LR
    TA["Alice's<br/>TokenAccount&lt;T&gt;<br/>active ↓"]:::conf
    Pool[("Pool&lt;T&gt;<br/>reserve")]:::pub
    Coin["recipient's<br/>Coin&lt;T&gt;"]:::pub

    TA ==>|"unwrap (amount)"| Coin
    Pool -.->|"withdraw"| Coin

    classDef pub fill:#fef9c3,stroke:#a16207,color:#713f12;
    classDef conf fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;
```

## Repository Structure

- **[`move/`](move/)** -- on-chain Move contracts, including:
  - **[`contra.move`](move/sources/contra.move)** -- main entry point with the high-level interfaces for both issuers and users; see the module-level doc comment at the top of the file for the full list of flows.
  - **[`twisted_elgamal.move`](move/sources/twisted_elgamal.move)** -- the Twisted ElGamal encryption scheme used on-chain.
- **[`ts-sdk/`](ts-sdk/)** -- TypeScript SDKs that mirror the Move modules:
  - **[`ContraClient`](ts-sdk/src/client.ts)** -- client SDK, including all the user flows.
  - **[`ContraAuditor`](ts-sdk/src/auditor.ts)** -- auditor SDK: recovers user viewing keys from on-chain registration data.
- **[`apps/kaisho/`](apps/kaisho/)** -- example wallet demonstrating the full user flow (including wrap, transfer, unwrap). Also includes an issuer setup page that deploys the BU test token and Contra contracts to Sui devnet or testnet, and an auditor view that uses the auditor SDK to inspect any token account's decrypted balance and history. Check out the deployed [Kaisho Wallet](https://kaisho-wallet.vercel.app/)!
- **[`apps/closed-loop/`](apps/closed-loop/)** -- example of a permissioned confidential token: a third-party token (BU) is wrapped 1:1 into a pool-backed token (pBU), with registration gated by a whitelist. Useful as a reference for B2B settlement setups among a closed group of participants who mutually trust each other to handle compliance off-chain.
- **[`apps/throttler/`](apps/throttler/)** -- example of a permissioned confidential token whose `unwrap` is delayed: calls go through a wrapper that parks the unwrapped coin in a shared `ThrottledPool` and appends a per-address pending entry; the user can `take` the coin only after a configurable `min_duration` has elapsed. The issuer can adjust the delay or overwrite any per-address queue to seize tokens. Useful as a reference for compliance flows that require a withdrawal window for review or seize.
- **[`apps/payment-channel/`](apps/payment-channel/)** -- example of **a unidirectional payment channel built on top of confidential tokens**. A `Channel<T>` shared object owns a confidential `Account` via object-owner auth (`as_object()`); the sender funds it once and signs off-chain a sequence of monotonically-increasing transfers paying a fixed receiver. The receiver settles the latest transfer as a sponsored transaction, and an inactivity timeout lets the sender reclaim the residual. Every transfer amount, the locked balance, and the sender's residual remain encrypted on chain — even from the receiver, who only learns the per-transfer amount they decrypt with their own viewing key. Bundles both the Move contract ([`payment_channel.move`](apps/payment-channel/move/payment_channel/sources/payment_channel.move)) and a TypeScript package (`sender` / `receiver` / `setup` / `deploy` / `client` modules plus an e2e test), and serves as a canonical reference for the `as_object()` auth constructor.
- **[`utils/`](utils/)** -- shared helpers for testing and interacting with Sui, used by the apps and the e2e tests.

> **AI disclaimer:** The code under `apps/` and all tests across the repository were written to some extent by LLMs.

## Encryption In Use

Confidential balances and transfer amounts are encrypted with **Twisted ElGamal** over Ristretto255. The scheme uses two generators with unknown discrete-log relationship: the standard generator `g` and a hash-to-curve derived `h`. For a public key `pk = x * g`, the encryption of a message `m` with random scalar `r` is the pair

```
c = r * g + m * h    (ciphertext)
d = r * pk           (decryption handle)
```

To decrypt with secret key `x`, the holder computes `c - d / x = m * h` and then recovers `m` by solving the discrete log `m = log_h(m * h)`. Encryptions are additively homomorphic: adding two ciphertexts component-wise yields an encryption of the sum of the plaintexts under the sum of the randomizers.

### Message in the exponent, u16 limbs

Because the message lives in the exponent, decryption requires solving a discrete log -- which is only practical for small ranges. To keep balances decryptable while still covering the full `u64` range, every amount is split into four `u16` limbs and each limb is encrypted independently:

```
amount = l0 + l1 * 2^16 + l2 * 2^32 + l3 * 2^48
```

A confidential balance is therefore four Twisted ElGamal ciphertexts. Decryption uses baby-step giant-step against a precomputed table, which makes recovering plaintexts up to ~2^32 per limb practical on commodity hardware.

### Bounded aggregation

The homomorphism lets the contract fold incoming encrypted deposits into the running encrypted balance without decrypting, but each addition can grow a limb beyond its original `u16` range. Starting from limbs of at most `2^16`, summing `k` such ciphertexts produces limbs of at most `k * 2^16`. The contract caps `k` at `2^16`, so each limb stays below `2^32` and remains decryptable from the precomputed table. This bound is tracked on-chain: after roughly `2^16` deposits without a merge, further deposits are rejected until the recipient merges the pending balance into the active one (which resets the bound).

## Balance Model

A confidential token account holds three separate balances:

| Balance | Description |
|---|---|
| **Active encrypted** | The spendable balance. All outgoing transfers and unwraps deduct from this. |
| **Pending encrypted** | Encrypted deposits received from other accounts, awaiting a merge. |
| **Pending public** | Public coin deposits (wraps), also awaiting a merge. |

Incoming deposits always go to the pending balances, never directly to the active one. This is a deliberate design choice: transfer, unwrap, and key-rotation transactions all commit to a specific snapshot of the active encrypted balance in their zero-knowledge proof, so if the active balance were modified by a concurrent deposit the proof would become invalid. Keeping deposits in a separate pending pool prevents this interference.

The account owner (indirectly) calls `merge` to fold pending deposits into the active balance when they want to spend them.

### Merge-then-spend and optimistic failure

The TS-SDK's `transfer` and `unwrap` methods default to `merge: true`, which prepends a `merge` call to the same transaction. This lets the user spend their full balance (active + pending) in one step. However, because the proof is computed from the balance the SDK observed at construction time, there is a race:

- If no deposit arrives between SDK construction and chain execution, the transaction succeeds in full.
- If a new deposit arrives in that window, the pending balance the SDK assumed is stale. The chain executes the `merge` successfully (folding the old pending into active), but then fails the transfer/unwrap proof and emits a `TryTransferFailedEvent` (or `TryUnwrapFailedEvent`) instead of aborting — leaving the user's funds intact.

In the failure case, a second attempt with `merge: false` will succeed immediately, because the previously-pending deposits have already been folded into the active balance by the first transaction's `merge` call, so the proof now only needs to match the active balance and is unaffected by any further deposits that may have arrived in the meantime.

## For Token Issuers

### Normal token flow

Issuing a token on Sui doesn't require anything specific to this project. The usual steps apply:

1. Create a Sui wallet.
2. Deploy your token `T` (a standard `Coin<T>` package).
3. Use the returned `TreasuryCap<T>` to mint supply, manage the deny list, and perform any other treasury operations.


### Enabling confidential transfers for `T`

Once `T` exists as a normal Sui coin, the issuer decides how confidential transfers are enabled for it. See [`contra.move`](move/sources/contra.move) for the full list of issuer flows. At a high level there are two options:

- **Permissionless** -- any holder of `T` can use confidential transfers freely. The issuer still retains global controls (see below) via `TreasuryCap<T>` and `ManagementCap<T>`.
- **Permissioned** -- the issuer installs a policy that gates some user flows behind the issuer's own contract (e.g., for KYC, screening, or rate limiting). 

#### Permissionless setup

1. Call [`new_confidential_token<T>`](move/sources/contra.move) with the shared `TokenRegistry` and a `&mut TreasuryCap<T>`. This creates the `ConfidentialToken<T>` object and returns a `ManagementCap<T>` to the caller.
2. Share the `ConfidentialToken<T>` via [`share_confidential_token`](move/sources/contra.move) so users can interact with it.
3. (Optional) Use the `ManagementCap<T>` to set global freeze admins who can pause the confidential token in an emergency.
4. (Optional) The issuer can always freeze accounts and seize tokens.

After this, users can register token accounts, wrap `Coin<T>` into confidential balances, transfer privately, and unwrap back to `Coin<T>` without further action from the issuer.

See [`token_issuer.ts`](ts-sdk/test/e2e/token_issuer.ts), function `init`, for an end-to-end example of the steps above.

#### Permissioned setup

In addition to the steps above, the issuer can gate selected user flows behind their own contract by calling [`set_policy`](move/sources/contra.move) on the `ConfidentialToken<T>` with a witness type `W` and the bitmap of operations (`register`, `wrap`, `unwrap`) that should become permissioned. The issuer's contract then exposes wrapper functions that authenticate the caller however it likes (KYC list, allowlist, rate limit, ...) and calls the corresponding flows.

See the [closed-loop app](apps/closed-loop/) for an example that gates `register` behind a whitelist.


## Compliance

Confidential tokens are private *by default*, but issuers retain a layered set of controls so they can meet regulatory and operational requirements without giving up that default. All of the controls below are exposed through [`contra.move`](move/sources/contra.move).

### Per-account freezing

The issuer (or anyone holding the underlying token's `DenyCapV2`) can add an address to the Sui deny list for `T`. A frozen address can no longer send or receive confidential transfers, wrap, or unwrap; removing the address from the deny list restores access.

Independently, freeze admins designated by the issuer via `ManagementCap<T>` can freeze an individual `TokenAccount<T>`, blocking it from transferring, wrapping, or unwrapping. Only the issuer (`TreasuryCap<T>`) can unfreeze an account.

Freezing only blocks future activity — it does not move any funds.

### Global pause

Two independent kill switches stop *all* activity for a confidential token, intended for incident response:

- The token's own `is_active` flag, flipped off by any of the freeze admins the issuer has designated via `ManagementCap<T>` (so a non-issuer operator can pause without holding treasury authority). Only the issuer (`TreasuryCap<T>`) can lift the pause.
- The underlying coin's deny-list global pause, controlled via the standard Sui `DenyCapV2`, which has the same effect from the layer below.

### Seizing and direct balance writes

The issuer (`TreasuryCap<T>`) can overwrite any account's encrypted balance directly, bypassing the homomorphic accounting. This is the "seize" / "burn" / "reset" lever for cases where the issuer must intervene by force — court orders, lost-key recovery, fraud reversal. Because it sidesteps normal flow, the caller is responsible for keeping the total confidential supply consistent with the public pool of `Coin<T>` (typically by pairing the write with a matching wrap/unwrap in the same transaction).

### Auditor visibility

Alongside the controls above, the issuer can register one or more auditor public keys so designated parties can decrypt balances and transfers off-chain without participating in transactions. See [For Auditors](#for-auditors) for the onboarding model and the per-account auditing design.

### Selective disclosure

Independently of the auditor flow, a user may voluntarily reveal a decrypted value — a balance or the amount on a specific `TransferEvent` — alongside a zero-knowledge proof that the cleartext matches the on-chain ciphertext under their public key. The verifier checks the proof against the public key without learning the user's secret key.

### Permissioned user flows [advanced]

By default `register`, `wrap`, and `unwrap` are open to any holder of `T`. The issuer can install a policy that gates any subset of those operations behind their own contract via a witness type. The wrapper functions are then free to enforce arbitrary checks — KYC, sanctions/screening lists, allowlists, rate limits, per-user caps — before authorizing the underlying flow. Confidential transfers between already-registered accounts remain permissionless even under the strictest policy, so user-to-user privacy is unaffected. The [closed-loop app](apps/closed-loop/) is an example that gates `register` behind a whitelist.


## For Auditors

An auditor is a passive reader of confidential balances and transfers for a given confidential token: they hold a or more secret keys whose public counterparts are registered on-chain by the issuer, and use them off-chain to decrypt user data. Auditors never sign protocol transactions.

Many confidential transfer protocols implement **per-transaction auditing**, where the sender attaches an auditor-readable copy of each transfer amount to every transaction. Our current design instead uses **per-account auditing**: the user encrypts their secret key once at registration (or on key rotation) to the current auditor key set, and from then on auditors derive transfer-level visibility for free by decrypting that one key and reading the user's account state. This is cheaper for users (no extra ciphertext or proof per transfer) and simpler for auditors (e.g., stateless access to balances).
See [Auditor Support in Confidential Transfers](AUDITORS.md) for more details on the per-transaction and per-account auditing.

### Onboarding flow

1. **Generate an auditor keypair off-chain.** Auditors generate a Twisted ElGamal keypair `(sk, pk)` over Ristretto255 and hand the **public key** to the token issuer.
2. **Issuer rotates the on-chain key set.** The issuer calls [`update_auditors`](move/sources/contra.move) with the new set of public keys (typically the existing set plus the new auditor's `pk`). Each rotation bumps the on-chain `version` counter on the token's `Auditors` struct, and records this auditor's index within the new `pks` vector. The auditor needs that `(version, index)` pair to know where its handle lives in every user's `VerifiedKeyEncryption`.
3. **Collect historical secrets.** The auditor assembles a `Map<version, (index, secretKey)>` covering every on-chain version it wants to be able to decrypt for. For versions that the auditor itself generated, the secret is its own. For older versions (set up before this auditor existed), the issuer or prior auditors must hand over the corresponding secrets — otherwise accounts that registered against those older versions remain opaque to this auditor.
4. **Initialize [`ContraAuditor`](ts-sdk/src/auditor.ts).** Construct the SDK with that version map plus a precomputed discrete-log table (the larger `numBits` is, the faster decryption will be).

### Reading a user's data

Once initialized, the auditor can call `getTokenAccount(address)` on the SDK. It fetches the on-chain `TokenAccount<T>`, decrypts the user's secret key, and returns a fully-keyed `TokenAccount` object. That object can then be passed to `ContraClient.getBalance` (active and pending balances) or to `EncryptedAmount.decrypt` for amounts that appear in event payloads encrypted to that user.

See the auditor cases in [`core_flow.test.ts`](ts-sdk/test/e2e/core_flow.test.ts) for end-to-end examples of constructing a `ContraAuditor` and using it to decrypt user balances across auditor key rotations.

## Status

Known gaps in the current implementation:

- **Cryptography is not finalized.** The protocol and implementations are still work in progress and should not be treated as production-ready.
- **No high-level byte-array entry points on-chain.** The Move API takes ciphertexts and proofs, for example, as already-deserialized structs, so callers currently assemble each flow as a large PTB that constructs every input piece-by-piece.
- **Client SDK is not yet designed for wallets.** `ContraClient` targets the example apps and test suites in this repo: it assumes the calling process can hold the user's viewing key directly and builds whole transactions.
- **Client SDK, no permissioned operations.** `ContraClient` only builds calls against the permissionless entry points. Wrapper calls into issuer-defined permissioned `register` / `wrap` / `unwrap` flows must currently be assembled by hand in the issuer's own client code.
- **Kaisho app stores user secrets in browser local storage.** The example wallet currently persists viewing/secret keys to local storage only; a future version will use [Seal](https://github.com/MystenLabs/seal) for managed secret storage.
- **Standalone Move package.** The contract is currently a standalone Move package; later it will be deployed as part of the protocol.
