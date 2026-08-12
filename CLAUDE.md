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
- **U64 amounts encoded as four u16 limbs** to prevent overflow when adding encrypted values; an `EncryptedBalance<T>` tracks a count of merged u16-bounded values that bounds limb growth so it stays decryptable
- Decryption uses baby-step giant-step discrete log solving (up to ~2^32 range)
- **Bulletproofs** range proofs (Bünz et al., 2018), generated client-side, compatible with `dalek-cryptography` / `fastcrypto` so proofs verify on-chain

### Move Contract (`move/sources/`)
- **contra.move**: Main contract — `TokenRegistry`, `AccountRegistry`, `Account`, `ConfidentialToken<T>`, `ManagementCap<T>`. Orchestrates register, wrap (public→confidential), unwrap (confidential→public), and transfer operations. Supports a permissioned mode where `register`/`wrap`/`unwrap` can be gated behind an issuer policy. Uses Sui dynamic fields for account state. Each token's balance is keyed under a per-token `TokenAccount.pk` (a `twisted_elgamal::PublicKey`), chosen explicitly at `register<T>(account, auth, pk)` and rotated explicitly via `rekey_token_account<T>(account, auth, new_pk, ...)` — per-token keys are independent of each other and of the account key. Keys entering the protocol are all `PublicKey` (non-identity by construction). `Account.default_pk` is an **optional** default key (`Option<PublicKey>`): the only thing it drives is `register_with_default_pk`. `set_default_pk_as_sender` sets or clears it (`Option`, O(1), touches no balance). Key rotation is lazy: `rekey_token_account<T>` requires the token's `pending` empty (merge first) and re-keys `active` from `TokenAccount.pk` to the supplied `new_pk` under a per-token DDH (`balance::try_set_public_key`); the optimistic sibling `try_rekey_token_account_and_unpause<T>` soft-fails (emits `TryTokenRekeyFailedEvent`, leaves the token stale) instead of aborting, and on success resumes deposits (`accepts_deposits = true`), so `set_default_pk_as_sender` + several re-keys can ride in one PTB without pausing. Deposits land under the receiver's `TokenAccount.pk` (senders read the per-token key), so `active`/`pending` never mix keys and a stale token keeps receiving under its old key until re-keyed. Deposits never auto-register: `wrap` and `add_to_batch` abort with `EReceiverNotRegistered` if the receiver has no `TokenAccount<T>`. For a permissionless-register token whose owner set `Account.default_pk`, anyone can create one on the receiver's behalf up front with `register_with_default_pk<T>(account, ct)` (keyed at `Account.default_pk`; aborts `EDefaultPkNotSet` if unset, `ERegistrationNotPermissionless` if the token's `register` op is permissioned), or its idempotent sibling `try_register_with_default_pk<T>` which no-ops instead of aborting when the token account already exists — the caller prepends the `try_` variant to the same PTB before a `wrap`/`transfer` to an as-yet-unregistered receiver (deposits never auto-register), so concurrent registrations for the same receiver don't abort each other. Deposits (`wrap` / `add_to_batch`) are gated on the per-`TokenAccount` `accepts_deposits`. Auditing is **per-transfer** and supports multiple auditors: when a token has auditor keys, `batched_transfer` takes an `auditors::AuditorPackage` (the `DecryptionHandles` for every (auditor, receiver) pair, flat, plus one `nizk::DdhProof` per (receiver, u32-limb) anchoring each auditor handle to the receiver's own range-proven u32 commitment), checked in `auditors::verify_transfer` against the `current_pks` set, else the `previous_pks` set (rotation grace).
- **auditors.move**: `Auditors` — a token's auditor keys as two vectors `current_pks` (tried first) / `previous_pks` (also accepted, for a grace window), which need not be the same length (empty `current_pks` = auditing disabled going forward; steady state has them equal; a change points `current_pks` at the new set while `previous_pks` still holds the outgoing set — the set can also shrink or empty out during the grace; no expiration epoch — the caller drives grace via `update`). `AuditorPackage` is the per-transfer data a sender attaches: the `DecryptionHandles` for every (auditor, receiver) pair — flat and auditor-major (`M*N` entries for `M` keys, `N` receivers) — plus one `nizk::DdhProof` per (receiver, u32-limb) (`2*N` proofs, receiver-major). Each derived u32-limb commitment reuses the receiver's range-proven commitment (only the handle differs per key), and the receiver's own u32 decryption handle already anchors that limb's blinding `ρ̃` to the commitment; so per (receiver, limb) a single shared-witness DDH over bases `[pk_receiver, pk_auditors…]` proves every auditor handle re-keys the same `ρ̃` — no auditor range/commitment re-proof needed. `verify_transfer(auditors, receiver_amounts, auditor_package, dst)` owns the whole per-transfer check: it pairs each receiver amount's two u32 handles (`encrypted_amount::handles_u32`) with the auditor handles and every (receiver, u32-limb) DDH must verify under `current_pks`, else the whole set is retried under `previous_pks`; it enforces the presence policy (no-data allowed iff `current_pks` empty; data allowed iff `current_pks` **or** `previous_pks` non-empty) and asserts the package's auditor count (`handles.length() / n`) matches `current_pks` or `previous_pks` (`EMismatchedAuditorCount`), then returns, per receiver, one `DecryptionHandles` per auditor (regrouped for events) + the verifying key vector. `update(auditors, current_pks, previous_pks)` replaces both vectors (any lengths — the sender's package matches one set or the other by its key count).
- **events.move**: All events emitted by the package and the `public(package)` `emit_*` functions that construct and emit them. `contra.move` (and any future module) emits through these named entry points rather than building event literals inline. Note: the on-chain event type tag's module segment is `events` (e.g. `<pkg>::events::TransferEvent<T>`), which is what off-chain consumers filter on.
- **encrypted_amount.move**: `EncryptedAmount` (four encrypted u16 limbs) and `WellFormedProof` (a Bulletproof range proof + one witness-folded ElGamal consistency proof per amount, covering its four same-key limbs at constant proof size). `encrypted_amount::verify(proof, amount, dst)` checks the pair against a caller-supplied Fiat-Shamir DST and returns a bool; consumers (`contra.move`) call it before trusting the amount. Bulletproof range checks delegate to `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255`, binding the same DST into the proof transcript. For per-transfer auditing, `ciphertexts_as_u32_limbs` derives the two u32-limb auditor commitments (`C_0 + 2^16 C_1`, `C_2 + 2^16 C_3`) from the receiver's u16 limbs, and `with_decryption_handles(wfea, handles)` pairs them with a `DecryptionHandles`' two handles into the amount's two auditor `Encryption`s — reusing the range-proven receiver commitments, so no separate auditor range proof is needed. `as_u32_encryptions(ea)` folds the four u16 limbs into the two u32-limb `Encryption`s with **both** ciphertext and handle folded (`(C_0+2^16 C_1, D_0+2^16 D_1), (C_2+2^16 C_3, D_2+2^16 D_3)`) — the compact, receiver-decryptable form emitted on `TransferEvent` (so consumers read the u32 commitments directly instead of regrouping four limbs).
- **balance.move**: `EncryptedBalance<T>` — an account's confidential balance (an `EncryptedAmount` plus a count of merged u16-bounded values that bounds limb growth) — and the linear coins that move value in/out of it, `PublicCoin<T>` and `EncryptedCoin<T>`. All are `phantom`-parameterized by the token type, mirroring `sui::balance::Balance<T>` / `sui::coin::Coin<T>`, so different token types can't be mixed. The balance has only `store` (no `copy`/`drop`) and is mutated in place: split (`try_split_to_public` / `try_split_batch`), merge (`merge_public` / `merge_encrypted` / `merge`), verified re-state (`try_update` / `set_public_key`), and `TreasuryCap`-gated issuer overrides (`overwrite_unchecked` / `clear_unchecked`). `try_split_batch` splits receiver-keyed `EncryptedCoin`s off the balance: the transfer total's commitment is reconstructed from the receiver amounts (the sender and receiver commitments are identical), its single sender-keyed decryption handle (`total_handle`) is supplied by the caller and proven well-formed by an ElGamal consistency proof, and a DDH balance proof shows the balance drops by exactly that total. The sender therefore never sends per-limb sender-keyed handles.
- **twisted_elgamal.move**: On-chain `Encryption` type (ciphertext + decryption handle), homomorphic add/sub, consistency verification. Also the `PublicKey` newtype over `Element<G>`, built through the `public_key` constructor that rejects the group identity — the single boundary that enforces non-identity, so every entry point taking a key (`register`, `rekey_token_account`, `set_default_pk_*`, `new_confidential_token`/`update_auditors`) and every stored key field takes a `PublicKey` rather than re-checking.
- **nizk.move**: Fiat-Shamir NIZKs over Ristretto255 — `DdhProof` (shared-witness DDH over a vector of base/image pairs: the classic Chaum-Pedersen tuple is the two-pair case, used for balance/equality proofs; per-token key rotation is the five-pair case, one `w` re-keying the token's public key and all four limb decryption handles at once; per-transfer auditing is the `(1+M)`-pair case, one `ρ̃` mapping the bases `[pk_receiver, pk_auditors…]` to the receiver's own u32 handle plus each auditor's re-keyed handle for that limb) and `ElGamalProof` (witness-folded twisted ElGamal well-formedness over any number of same-key ciphertexts at a constant `2` points + `2` scalars; a single ciphertext is the batch-of-1 case). Both verifiers reduce to shared Schnorr row-checkers and bind the statement bases into the Blake2b256 challenge transcript, so the same proof types are reusable across different DDH/ElGamal contexts.
- **deny_list.move**: Sui DenyList integration for per-address freezing and global pause (KYC/compliance).

### TypeScript SDK (`ts-sdk/src/`)
Client-side cryptographic operations and transaction building, mirroring the Move modules.

- **client.ts**: `ContraClient` -- builds Move call transactions for register, wrap, unwrap, transfer, and account management. Deposits never auto-register: `wrap` (async) and `transferBatch` require every receiver to already have a `TokenAccount<T>` — they fetch each receiver's state and throw `TokenAccountDoesNotExistError` otherwise. To deposit to an as-yet-unregistered receiver the caller prepends a `tryRegisterWithDefaultPk({ receiver, tokenType })` call to the same PTB themselves (permissionless-register tokens only; the race-safe `try_` variant, so concurrent registrations for the same receiver don't abort each other). Transfers attach per-transfer auditor data (`buildAuditorData`: the flat auditor-major handles for every (auditor, receiver) pair + one `DdhNizk` per (receiver, u32-limb) anchoring each auditor handle to the receiver's own u32 handle) when `getAuditor(tokenType)` reports any current keys (`currentPks`). `newAccount({ owner })` creates the (permissionless) account with no key; the optional default key is set separately with `setDefaultPkAsSender` (built as `Option<PublicKey>` via `buildOptionalPublicKey`), and `register` passes the token's key explicitly (`tokenAccount.publicKey`, wrapped in a `PublicKey` via `buildPublicKey`). Key rotation: `setDefaultPkAsSender` sets/clears the optional default key (O(1)), `rekeyTokenAccount` / `tryRekeyTokenAccount` re-key a token to an explicit `newTokenAccount.publicKey` (independent of the account key; the latter soft-fails), and `tryRekeyTokenAccounts({ rotations })` (the batched, soft-failing plural of `tryRekeyTokenAccount`: optimistic per-token merge + `tryRekeyTokenAccount` for every `(current, new)` pair in one PTB — each token re-keys from its own current key to its own paired new key; racing tokens just soft-fail and stay stale; it does not touch the account default key — use `setDefaultPkAsSender` for that). `getTokenKeys(address, tokenTypes)` reports each supplied token's current key (a `TokenKeyStatus[]`; a token — or account — that doesn't exist is reported `registered: false`). An app passes the tokens it supports and uses it to see each token's current key, to detect which tokens a `tryRekeyTokenAccounts` left un-rekeyed (soft-failed — the token still reports its old key), and whether an old key is still in use (a token can only be re-keyed/decrypted with the key it currently reports, so the old key must be retained until no token still reports it).
- **auditor.ts**: `ContraAuditor` -- per-transfer auditor. Holds one or more auditor private keys (`addKey` adds more; `publicKeys` lists them) and `decryptTransferAmount(event)` recovers a transfer's amount from a decoded `TransferEvent` (returns `null` when the transfer carried no auditor data): it selects the held key whose public key matches one of the event's `auditor_pks` and reads that key's handle set (at the same index in `auditor_decryption_handles`), takes the two u32-limb commitments straight from the event's `encrypted_amount_receiver` (now two u32 `Encryption`s, no regrouping), pairs each with the matching handle, and BSGS-decrypts. Holding the rotated-out keys lets one auditor read transfers made before and after a key rotation. The auditor never learns a user's viewing key.
- **token_account.ts**: Client-side representation of a user's token account state. Includes `decryptWithProof(ciphertext, table)` for the selective-disclosure flow: given any `Ciphertext` (e.g. a collapsed balance or a `TransferEvent`'s encrypted amount), it returns `{ value, proof }` -- a plaintext and a zero-knowledge proof of correct decryption verifiable with `ciphertext.verifyDecryption(pk, value, proof)`. `decryptAmount(limbs, table)` decrypts a received transfer amount from the event's two u32-limb ciphertexts (`n_0 + 2^32 n_1`). `recoverSentAmount(limbs, point, batchIndex, table)` lets a sender recover its own outgoing amount from the same two u32 limbs: the sender stores no per-transfer secret and instead re-derives the per-u32-limb blindings from `seed = HKDF(sk * point)` (the `TransferEvent`'s `seed_point`) — each is the fold `ρ̃_k = ρ_{2k} + 2^16 ρ_{2k+1}` — and reads the value off the commitments (which equal the receiver's), with no sender-keyed decryption handle.
- **twisted_elgamal.ts**: Key generation, encryption/decryption (`decrypt` via handle + `decryptWithBlinding` from a known blinding for the sender-recovery path), precomputed discrete log table for fast brute-force decryption.
- **transfer_randomness.ts**: Per-transfer randomness for batched transfers. `sampleTransferRandomness(senderPk)` draws one scalar `t`, exposes the point `P = t*G` (sent on chain) and seed-derived per-(recipient, limb) blindings from `seed = HKDF(t*senderPk)`; `recoverTransferRandomness(sk, P)` reproduces the same blindings from `sk * P`. Client-only KDF (HKDF-SHA256), never recomputed on chain.
- **pedersen.ts**: Pedersen commitment creation and verification.
- **nizk.ts**: NIZK proof generation/verification mirroring `nizk.move` — `DdhNizk` (shared-witness DDH over base/image pairs; two-pair balance/equality case, five-pair re-key case, `(1+M)`-pair per-transfer auditor case; `client.ts`'s `buildAuditorData` builds one per (receiver, u32-limb)) and `ElGamalNizk` (witness-folded batch over same-key ciphertexts at constant size; `helpers.ts`'s `buildWellFormedProof` folds each amount's four limbs into one proof).
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
