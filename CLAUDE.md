# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code Style

All code files must include this copyright header at the top:
```
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
```

### Comment Writing Guidelines

**Do NOT comment the obvious** -- comments should not simply repeat what the code does.

**When to comment**:
- Non-obvious algorithms, cryptographic constructions, or protocol details (cite the paper or spec where possible)
- Hidden invariants, preconditions, or assumptions that are not enforced by types
- Subtle security or soundness considerations (e.g., why a check is needed, what happens if it is removed)
- Workarounds for specific bugs or upstream limitations
- Temporary placeholders or stubs (mark with `TODO:`)

**When NOT to comment**:
- Self-descriptive function calls and variable assignments
- Basic control flow (if/for/while)
- Restating type signatures
- The current task, fix, or PR ("added for X", "used by Y") -- this belongs in commit messages

## Documentation

When you change code, update the surrounding documentation in the same change:
- The top-level `README.md` is the only place that explains the project (what it is, properties, issuer/user flows). Update it when public-facing behavior, properties, or flows change.
- Sub-directory READMEs (`move/README.md`, `apps/kaisho/README.md`) only cover how to build and test the code in that directory — do not duplicate project-level explanation there.
- The "Architecture" section in this `CLAUDE.md` -- update it when modules are added, removed, renamed, or change responsibility.
- Module-level doc comments in `move/sources/*.move` and TSDoc in `ts-sdk/src/*.ts` -- keep them in sync with the code below them.

If a change makes any of the above stale, fix it in the same change rather than leaving a follow-up.

## Project Overview

Confidential transactions system for the Sui blockchain enabling confidential token transfers using homomorphic encryption and zero-knowledge proofs. Two main components: a Move smart contract and a TypeScript cryptographic SDK, plus an example wallet app.

## Build & Test Commands

### Move (in `move/`)
```
sui move build          # Build the Move package
sui move test           # Run all Move tests
sui move test <filter>  # Run specific Move test by name
```

After creating or editing any `.move` file, format it before pushing:
```
npx @mysten/prettier-plugin-move -w <file>   # or -c to check
```
CI's "Check Move formatting" job runs this plugin over every `.move` file (excluding
`build/`), and `sui move build` does **not** catch formatting issues — so a build-clean
file can still fail CI.

### WASM bindings (in `utils/bulletproofs-wasm/`)
```
pnpm build:wasm         # Build both wasm-pack targets (nodejs/ + web/)
```
`@contra/bulletproofs-wasm` wraps `fastcrypto::bulletproofs` and is consumed by
`ts-sdk` via a `file:` dependency. Requires the Rust toolchain with the
`wasm32-unknown-unknown` target plus `wasm-pack`. The `nodejs/` and `web/`
outputs are gitignored build artifacts — a fresh checkout must run `build:wasm`
before building `ts-sdk`.

macOS note: a transitive C dependency (`blst`) is cross-compiled to wasm32, but
Apple's system `clang` has no wasm backend (`build:wasm` fails with "No available
targets are compatible with triple wasm32-unknown-unknown"). Install a
wasm-capable clang (`brew install llvm`) and point cc-rs at it for that target:
`CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang AR_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/llvm-ar pnpm build:wasm`.
Linux/CI uses the stock clang, which already targets wasm32 — no extra setup.

### TypeScript SDK (in `ts-sdk/`)
```
pnpm install            # Install dependencies
pnpm build              # Type-check + bundle (tsdown)
pnpm test               # Run all unit tests (vitest)
pnpm vitest <filter>    # Run specific test by name/path
```

## Important: Build the WASM bindings before ts-sdk

`ts-sdk` depends on `@contra/bulletproofs-wasm` (`file:../utils/bulletproofs-wasm`).
pnpm packs `file:` deps at install time, so run `pnpm build:wasm` in
`utils/bulletproofs-wasm/` *before* `pnpm install` in `ts-sdk/`. If you change the
Rust crate, rebuild the package and re-run `pnpm install --force` in `ts-sdk/`
so the freshly built `nodejs/` + `web/` outputs are re-packed.

## Important: Rebuild ts-sdk after changes

The app (`apps/kaisho`) consumes `ts-sdk` from its built `dist/` output, not the source. After any change to `ts-sdk/src/`, always run `pnpm build` in `ts-sdk/` before testing in the app. A stale dist will silently use old code and cause hard-to-diagnose runtime errors.

## Important: Recompile Move bytecodes for the kaisho app after Move changes

The kaisho app publishes contracts from a pre-compiled bytecode bundle at `apps/kaisho/public/bu_token_bytecodes.json`, which contains both the BU test token (`utils/move/test_token`) and the bundled `contra` modules (`move/sources`). After any change to either Move package, run `pnpm compile-move` in `apps/kaisho/` and commit the updated bytecodes file. `pnpm dev` recompiles automatically; `pnpm build` (and Vercel) does not.

## Architecture

### Cryptographic Foundation
- **Ristretto255** group throughout, with two generators: `g` (standard) and `h` (hash-to-curve derived, unknown discrete log relationship to `g`)
- **Twisted ElGamal** encryption with message-in-exponent: ciphertext `(c = r*g + m*h, d = r*pk)`, supporting homomorphic add/subtract
- **Pedersen commitments**: `commit = m*h + blinding*g`, additively homomorphic
- **U64 amounts encoded as four u16 limbs** to prevent overflow when adding encrypted values; a `BoundedEncryptedAmount` tracks a count of merged u16-bounded values that bounds limb growth so it stays decryptable
- Decryption uses baby-step giant-step discrete log solving (up to ~2^32 range)
- **Bulletproofs** range proofs (Bünz et al., 2018), generated client-side, compatible with `dalek-cryptography` / `fastcrypto` so proofs verify on-chain

### Move Contract (`move/sources/`)
- **contra.move**: Main contract — `TokenRegistry`, `AccountRegistry`, `Account`, `ConfidentialToken<T>`, `ManagementCap<T>`. Orchestrates register, wrap (public→confidential), unwrap (confidential→public), and transfer operations. Supports a permissioned mode where `register`/`wrap`/`unwrap` can be gated behind an issuer policy. Uses Sui dynamic fields for account state. Each `TokenAccount<T>` holds its value as a single `balance::Balances<T>`, keyed under a per-token public key chosen explicitly at `register<T>(account, auth, pk)` and rotated explicitly via `rekey_token_account<T>(account, auth, new_pk, ...)` — per-token keys are independent of each other and of the account key. Keys entering the protocol are all `PublicKey` (non-identity by construction). `Account.default_pk` is an **optional** default key (`Option<PublicKey>`): the only thing it drives is `register_with_default_pk`. `set_default_pk_as_sender` sets or clears it (`Option`, O(1), touches no balance). Key rotation is lazy: `rekey_token_account<T>` requires the token's `pending` empty (merge first) and re-keys `active` to the supplied `new_pk` under a per-token DDH (`balance::try_rekey`); the optimistic sibling `try_rekey_token_account_and_unpause<T>` soft-fails (emits `TryTokenRekeyFailedEvent`, leaves the token stale) instead of aborting, and on success resumes deposits (`accepts_deposits = true`), so `set_default_pk_as_sender` + several re-keys can ride in one PTB without pausing. Deposits land under the receiver's own `Balances` key, checked by `balance` itself (senders read the per-token key), so `active`/`pending` never mix keys and a stale token keeps receiving under its old key until re-keyed. Deposits never auto-register: `wrap` and `add_to_batch` abort with `EReceiverNotRegistered` if the receiver has no `TokenAccount<T>`. For a permissionless-register token whose owner set `Account.default_pk`, anyone can create one on the receiver's behalf up front with `register_with_default_pk<T>(account, ct)` (keyed at `Account.default_pk`; aborts `EDefaultPkNotSet` if unset, `ERegistrationNotPermissionless` if the token's `register` op is permissioned), or its idempotent sibling `try_register_with_default_pk<T>` which no-ops instead of aborting when the token account already exists — the caller prepends the `try_` variant to the same PTB before a `wrap`/`transfer` to an as-yet-unregistered receiver (deposits never auto-register), so concurrent registrations for the same receiver don't abort each other. Deposits (`wrap` / `add_to_batch`) are gated on the per-`TokenAccount` `accepts_deposits`. `batched_transfer<T>` takes the transfer's **raw** inputs — the per-receiver `EncryptedAmount`s and their re-encryption keys, the new sender balance, the total's decryption handle, and the ElGamal consistency + `RangeProofs` — and hands them to `balance::try_withdraw_batch`, which verifies them against the sender balance's own key and session before splitting the receiver-keyed coins off it — so the verified values never leave the module. The per-transfer auditor check then runs on those coins (`auditors::prepare_auditor_data(&coins, ..)`), and only when the balance proof verified: a soft-failed transfer credits nobody, so its auditor data goes unchecked. Auditing is **per-transfer** with at most one auditor key: when a token has an auditor key, `batched_transfer` takes an `auditors::AuditorPackage` (one `[lo, hi]` decryption handle pair per receiver plus one witness-folded `nizk::ElGamalProof` over all `2N` auditor ciphertexts, each pairing a receiver's own range-proven u32 commitment with its auditor handle), checked in `auditors::prepare_auditor_data` against the `current_pks` key, else the `previous_pks` key (rotation grace); each set holds ≤1 key.
- **auditors.move**: `Auditors` — a token's auditor key as two vectors `current_pks` (tried first) / `previous_pks` (also accepted, for a grace window), **each holding at most one key** (asserted by `new`/`update` via `ETooManyAuditors`; empty `current_pks` = auditing disabled going forward; a rotation points `current_pks` at the new key while `previous_pks` still holds the outgoing one; no expiration epoch — the caller drives grace via `update`). `AuditorPackage` is the per-transfer data a sender attaches: one `[lo, hi]` decryption handle pair per receiver plus one witness-folded `nizk::ElGamalProof` over all `2N` auditor ciphertexts (`N` pairs, one constant-size proof). Each auditor ciphertext pairs the receiver's own range-proven u32 commitment (`Ǎ = C_{2l} + 2^16 C_{2l+1}`, key-independent, re-derived on-chain via `encrypted_amount::ciphertexts_u32`) with the sender-supplied auditor handle `D = ρ̃ · pk_auditor`, forming a twisted-ElGamal encryption of the u32 limb under the auditor key; the single folded ElGamal proof shows every handle re-keys its commitment's blinding `ρ̃` to the auditor key — no auditor range/commitment re-proof needed (the commitment is shared with the receiver, which its own range/consistency proof already covers). `prepare_auditor_data(auditors, receiver_coins, auditor_package, session_id)` owns the whole per-transfer check (deriving its own Fiat-Shamir DST from the `SessionId`, so `contra.move` carries no transcript machinery): it builds the `2N` auditor ciphertexts (pairing each receiver's `ciphertexts_u32` with its handles) and the folded ElGamal proof must verify under `current_pks`, else under `previous_pks`; it enforces the presence policy (no-data allowed iff `current_pks` empty; data allowed iff `current_pks` **or** `previous_pks` non-empty) and asserts one handle pair per receiver (`EMismatchedAuditorCount`), then returns `Option<VerifiedAuditorHandles>` (the per-receiver `[lo, hi]` pairs tagged with the verifying key), held in the `TransferBatch` and drained one receiver at a time by `next` (pops the front pair + the key for each `TransferEvent`) before `finalize` calls `destroy_empty`, which aborts unless every pair was popped. `update(auditors, current_pks, previous_pks)` replaces both vectors (each ≤1).
- **events.move**: All events emitted by the package and the `public(package)` `emit_*` functions that construct and emit them. `contra.move` (and any future module) emits through these named entry points rather than building event literals inline. Note: the on-chain event type tag's module segment is `events` (e.g. `<pkg>::events::TransferEvent<T>`), which is what off-chain consumers filter on.
- **encrypted_amount.move**: `EncryptedAmount` (four encrypted u16 limbs) plus the verified-encryption types that gate what may enter a balance. `VerifiedEncryption` is an `Encryption` + its `PublicKey`, ElGamal-proven under `pk` (one witness-folded `nizk::ElGamalProof`) but **not** range-checked, so its committed value may exceed a u16 (e.g. a transfer total). `VerifiedEncryptedAmount` is four same-key limbs, ElGamal-proven (via `verify_encrypted_amount`); `InRangeVerifiedEncryptedAmount` adds a per-limb range check to `[0, 2^16)`. `verify_in_range(amounts, range_proofs, dst)` range-checks a batch of `VerifiedEncryptedAmount`s in one shot and promotes each to an `InRangeVerifiedEncryptedAmount` — the **only** constructor of that type, so an in-range amount is always range-checked. Range proofs are wrapped in `RangeProofs`, whose only production constructor (`new_range_proofs`) rejects an empty set (and PTBs can't fabricate the struct), so the on-chain range check can never be silently skipped; Move tests, which can't produce Bulletproof bytes, use the `#[test_only]` `assume_range_checked`. Bulletproof range checks delegate to `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255`, binding the same Fiat-Shamir DST into the transcript. For per-transfer auditing, `ciphertexts_u32(wfea)` returns the receiver's two u32-limb ciphertext commitments (`C_0 + 2^16 C_1`, `C_2 + 2^16 C_3`), which `auditors::verify_under` pairs with the sender-supplied auditor handles into the `2N` twisted-ElGamal ciphertexts the folded auditor proof covers (the commitment is key-independent, so it doubles as the auditor's — no separate auditor range/commitment proof is needed). The `TransferEvent` emits the raw four-limb `EncryptedAmount` (each limb `< 2^16`), so a receiver/sender wallet decrypts each limb with a single BSGS table lookup; the auditor folds the four u16 commitments into two u32 commitments off-chain to pair with its two u32 handles.
- **session.move**: `SessionId` — the 20-byte domain separator of one `(account, token)` pair, derived by `contra.move` at registration and stored on the `TokenAccount`. Every proof the package verifies against that account is bound to it: `session.ddh()` / `elgamal()` / `range_proof_16()` / `batch_ddh()` / `auditor_elgamal()` return `session id || protocol tag`, the tags being the ids shared with the ts-sdk (which reserves `100` for `PROTOCOL_VERIFIED_DEC`). `balance.move` and `auditors.move` derive their transcripts through it, so no caller supplies a DST.
- **balance.move**: `Balances<T>` — one account's balances of token `T`, all under a single key: the key itself (`pk`), the spendable `active` balance, the `pending` encrypted deposits, and `public_balance`, the wrapped-but-unmerged public deposits. `active`/`pending` are `BoundedEncryptedAmount` (an `EncryptedAmount` plus a count of merged u16-bounded values that bounds limb growth), encrypted value leaves as the abilityless `EncryptedCoin<T>`; public value never leaves as a value at all — `deposit_public(coin, pool)` sends the funds to `Pool<T>` and credits the plaintext `public_balance` in one step, and `try_withdraw_public(.., pool, ctx)` lowers the balance and pays out the `Coin<T>` in one step, so the two halves cannot come apart. `contra.move` supplies the pool's `UID`, whose field is private to it. `Balances<T>` and `EncryptedCoin<T>` are `phantom`-parameterized by the token type, mirroring `sui::balance::Balance<T>` / `sui::coin::Coin<T>`, so different token types can't be mixed (the inner `BoundedEncryptedAmount` needs no tag — it never leaves its parent). The module is **self-contained**: every amount is bound to the balance's own `pk` — the verifiers are private and key it themselves, and `deposit_encrypted` aborts `EInvalidPublicKey` unless an incoming coin is encrypted under it and every proof is verified against a Fiat-Shamir DST the module derives itself from the caller's `session::SessionId`; `contra.move` keeps only what isn't value (authorization, freezing, events). The API is deposits (`deposit_public` / `deposit_encrypted`, both capacity-checked against `EBalanceFull`), consolidation (`merge_deposits`), withdrawals — each taking raw amounts and proofs and verifying them privately (`try_withdraw_public`, returning a `Coin<T>` redeemed from the pool; `try_withdraw_batch`, which takes a transfer's raw amounts and proofs, verifies them privately and returns the receiver-keyed `EncryptedCoin`s — `amount()` peeks at one so the caller can run the auditor check against the coins it is about to credit), re-statement (`try_update_active`), key rotation (`try_rekey`, which aborts `EPendingDepositsMustBeMerged` unless `pending` is empty and swaps `pk` on success), and the unchecked issuer override `overwrite_unchecked`, whose `TreasuryCap` gate lives in `contra.move`. `try_withdraw_batch` reconstructs the transfer total's commitment from the receiver amounts (the sender and receiver commitments are identical), so only its single sender-keyed decryption handle is supplied by the caller and proven well-formed together with the new balance in one folded ElGamal proof; a DDH balance proof then shows the balance drops by exactly that total. The sender therefore never sends per-limb sender-keyed handles.
- **twisted_elgamal.move**: On-chain `Encryption` type (ciphertext + decryption handle), homomorphic add/sub, consistency verification. Also the `PublicKey` newtype over `Element<G>`, built through the `public_key` constructor that rejects the group identity — the single boundary that enforces non-identity, so every entry point taking a key (`register`, `rekey_token_account`, `set_default_pk_*`, `new_confidential_token`/`update_auditors`) and every stored key field takes a `PublicKey` rather than re-checking.
- **nizk.move**: Fiat-Shamir NIZKs over Ristretto255 — `DdhProof` (shared-witness DDH over a vector of base/image pairs: the classic Chaum-Pedersen tuple is the two-pair case, used for balance/equality proofs; per-token key rotation is the five-pair case, one `w` re-keying the token's public key and all four limb decryption handles at once) and `ElGamalProof` (witness-folded twisted ElGamal well-formedness over any number of same-key ciphertexts at a constant `2` points + `2` scalars; a single ciphertext is the batch-of-1 case, each transfer's amount consistency uses it, and per-transfer auditing folds all `2N` auditor ciphertexts of a batch into one). Both verifiers reduce to shared Schnorr row-checkers and bind the statement bases into the Blake2b256 challenge transcript, so the same proof types are reusable across different DDH/ElGamal contexts.
- **deny_list.move**: Sui DenyList integration for per-address freezing and global pause (KYC/compliance).

### TypeScript SDK (`ts-sdk/src/`)
Client-side cryptographic operations and transaction building, mirroring the Move modules.

- **client.ts**: `ContraClient` -- builds Move call transactions for register, wrap, unwrap, transfer, and account management. Deposits never auto-register: `wrap` (async) and `transferBatch` require every receiver to already have a `TokenAccount<T>` — they fetch each receiver's state and throw `TokenAccountDoesNotExistError` otherwise. To deposit to an as-yet-unregistered receiver the caller prepends a `tryRegisterWithDefaultPk({ receiver, tokenType })` call to the same PTB themselves (permissionless-register tokens only; the race-safe `try_` variant, so concurrent registrations for the same receiver don't abort each other). Transfers attach per-transfer auditor data (`buildAuditorData`: the auditor's `[lo, hi]` handle pair per receiver + one witness-folded `ElGamalNizk` over all `2N` auditor ciphertexts, each pairing the receiver's own u32 commitment with its auditor handle) when `getAuditor(tokenType)` reports a current key (`currentPks[0]`). `newAccount({ owner })` creates the (permissionless) account with no key; the optional default key is set separately with `setDefaultPkAsSender` (built as `Option<PublicKey>` via `buildOptionalPublicKey`), and `register` passes the token's key explicitly (`tokenAccount.publicKey`, wrapped in a `PublicKey` via `buildPublicKey`). Key rotation: `setDefaultPkAsSender` sets/clears the optional default key (O(1)), `rekeyTokenAccount` / `tryRekeyTokenAccount` re-key a token to an explicit `newTokenAccount.publicKey` (independent of the account key; the latter soft-fails), and `tryRekeyTokenAccounts({ rotations })` (the batched, soft-failing plural of `tryRekeyTokenAccount`: optimistic per-token merge + `tryRekeyTokenAccount` for every `(current, new)` pair in one PTB — each token re-keys from its own current key to its own paired new key; racing tokens just soft-fail and stay stale; it does not touch the account default key — use `setDefaultPkAsSender` for that). `getTokenKeys(address, tokenTypes)` reports each supplied token's current key (a `TokenKeyStatus[]`; a token — or account — that doesn't exist is reported `registered: false`). An app passes the tokens it supports and uses it to see each token's current key, to detect which tokens a `tryRekeyTokenAccounts` left un-rekeyed (soft-failed — the token still reports its old key), and whether an old key is still in use (a token can only be re-keyed/decrypted with the key it currently reports, so the old key must be retained until no token still reports it).
- **auditor.ts**: `ContraAuditor` -- per-transfer auditor. Holds one or more auditor private keys (keyed by pk-bytes in a `Map`; `addKey` adds more; `publicKeys` lists them) and `decryptTransferAmount(event)` recovers a transfer's amount from a decoded `TransferEvent` (returns `null` when the transfer carried no auditor data): it uses the held key whose public key matches the event's `auditor_pk` (an `Option`, `none` when auditing is disabled) and reads that auditor's two handles from `auditor_decryption_handles` (a flat length-0-or-2 vector), folds the event's four u16 commitments (`encrypted_amount_receiver`, a four-limb `EncryptedAmount`) into two u32-limb commitments, pairs each with the matching handle, and BSGS-decrypts. A token has at most one auditor key at a time, but holding the rotated-out keys lets one auditor read transfers made before and after a key rotation. The auditor never learns a user's viewing key.
- **token_account.ts**: Client-side representation of a user's token account state. Includes `decryptWithProof(ciphertext, table)` for the selective-disclosure flow: given any `Ciphertext` (e.g. a collapsed balance or a `TransferEvent`'s encrypted amount), it returns `{ value, proof }` -- a plaintext and a zero-knowledge proof of correct decryption verifiable with `ciphertext.verifyDecryption(pk, value, proof)`. `decryptAmount(limbs, table)` decrypts a received transfer amount from the event's four u16-limb ciphertexts (`Σ_k n_k · 2^{16k}`), each recovered with a single BSGS table lookup. `recoverSentAmount(limbs, point, batchIndex, table)` lets a sender recover its own outgoing amount from the same four u16 limbs: the sender stores no per-transfer secret and instead re-derives the per-limb blindings `ρ_k` from `seed = HKDF(sk * point)` (the `TransferEvent`'s `seed_point`) and reads the value off the commitments (which equal the receiver's), with no sender-keyed decryption handle.
- **twisted_elgamal.ts**: Key generation, encryption/decryption (`decrypt` via handle + `decryptWithBlinding` from a known blinding for the sender-recovery path), precomputed discrete log table for fast brute-force decryption.
- **transfer_randomness.ts**: Per-transfer randomness for batched transfers. `sampleTransferRandomness(senderPk)` draws one scalar `t`, exposes the point `P = t*G` (sent on chain) and seed-derived per-(recipient, limb) blindings from `seed = HKDF(t*senderPk)`; `recoverTransferRandomness(sk, P)` reproduces the same blindings from `sk * P`. Client-only KDF (HKDF-SHA256), never recomputed on chain.
- **pedersen.ts**: Pedersen commitment creation and verification.
- **nizk.ts**: NIZK proof generation/verification mirroring `nizk.move` — `DdhNizk` (shared-witness DDH over base/image pairs; two-pair balance/equality case, five-pair re-key case) and `ElGamalNizk` (witness-folded batch over same-key ciphertexts at constant size; `client.ts` / `helpers.ts` fold each amount's four limbs into one proof (`ElGamalNizk.prove`), and `client.ts`'s `buildAuditorData` folds all `2N` auditor ciphertexts of a batch into one).
- **bp.ts**: `getBulletproofs(moduleOrPath?)` — an async factory (mirroring `@mysten/walrus-wasm`'s `getWasmBindings`) that initializes the `@contra/bulletproofs-wasm` module once and returns bound, synchronous `batchRangeProof` / `verifyBatchRangeProof` functions, byte-compatible with `fastcrypto::bulletproofs`. `ContraClient` caches the result (`#getBulletproofs()`) and awaits it during a method's async phase, then passes the bound `batchRangeProof` into the proof-building helpers so the synchronous PTB thunks can call it. A `wasmUrl` client option is forwarded to the factory for browsers that can't auto-locate the asset.
- **ristretto255.ts**: Ristretto255 helpers (random scalars, point types) on top of `@noble/curves`.
- **contracts/**: BCS schemas mirroring the on-chain Move structs, auto-generated by `@mysten/codegen` from `move/sources/*.move`. Regenerate with `pnpm codegen` after any Move struct change — never hand-edit the files under `ts-sdk/src/contracts/`.
- **types.ts**, **helpers.ts**, **index.ts**: shared types, transaction-building utilities, and public exports.

Note on Fiat-Shamir hash functions:
- NIZKs use **Blake2b256** on both sides: `nizk.move` and `nizk.ts` (via `helpers.ts`'s `fiatShamirChallenge`) hash the same BCS-encoded transcript, so TS-built proofs verify on-chain. This applies to every proof type — including the client-side decryption-disclosure DDH proof, which uses the same challenge.
- Bulletproofs (`bp.ts` → `@contra/bulletproofs-wasm` → `fastcrypto` ↔ Sui `sui::rangeproofs`) use the **Merlin/STROBE** transcript so client and chain agree.

### WASM bindings (`utils/bulletproofs-wasm/`)
- **@contra/bulletproofs-wasm**: Standalone package wrapping `fastcrypto::bulletproofs` (Rust crate in `src/lib.rs`, built with `wasm-pack`). Ships two builds selected by `package.json` `exports` conditions: a `nodejs/` build (CommonJS, loads synchronously — its `init` is a no-op) and a `web/` build (needs an async `init`). `ts-sdk` consumes it via `file:` and wraps init in `bp.ts`'s `getBulletproofs()` factory. The package has no `"type": "module"` so the CommonJS `nodejs` build resolves cleanly.

### Apps (`apps/`)
- **kaisho/**: Example React/Vite wallet demonstrating the full flow (connect wallet, create account, wrap, transfer, unwrap) plus an issuer setup page that deploys the BU test token and Contra contracts to Sui devnet or testnet (the active network is chosen at runtime via the header picker; see `src/network.ts`). Consumes `ts-sdk` from its built `dist/`.

### Key Dependencies
- `@noble/curves` and `@noble/hashes` for TS cryptography
- `@mysten/sui` for Sui SDK integration — fullnode access is **gRPC only** (`SuiGrpcClient` / the transport-agnostic `core` API). The JSON-RPC client is deprecated upstream and must not be reintroduced. Event queries use `LedgerService.ListEvents` via a hand-written protobuf-ts stub in `apps/kaisho/src/grpc/listEvents.ts` (the fullnodes serve the method but the TS SDK doesn't generate a client for it yet; replace it with the SDK client once available).
- Sui Move 2024 edition standard library
