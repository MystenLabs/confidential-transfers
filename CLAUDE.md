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
- **contra.move**: Main contract — `TokenRegistry`, `AccountRegistry`, `Account`, `ConfidentialToken<T>`, `ManagementCap<T>`. Orchestrates register, wrap (public→confidential), unwrap (confidential→public), and transfer operations. Supports a permissioned mode where `register`/`wrap`/`unwrap` can be gated behind an issuer policy. Uses Sui dynamic fields for account state.
- **events.move**: All events emitted by the package and the `public(package)` `emit_*` functions that construct and emit them. `contra.move` (and any future module) emits through these named entry points rather than building event literals inline. Note: the on-chain event type tag's module segment is `events` (e.g. `<pkg>::events::TransferEvent<T>`), which is what off-chain consumers filter on.
- **encrypted_amount.move**: `EncryptedAmount` (four encrypted u16 limbs) and `WellFormedProof` (a Bulletproof range proof + one witness-folded ElGamal consistency proof per amount, covering its four same-key limbs at constant proof size). `encrypted_amount::verify(proof, amount, dst)` checks the pair against a caller-supplied Fiat-Shamir DST and returns a bool; consumers (`contra.move`) call it before trusting the amount. Bulletproof range checks delegate to `sui::rangeproofs::verify_bulletproofs_with_dst_ristretto255`, binding the same DST into the proof transcript.
- **balance.move**: `EncryptedBalance<T>` — an account's confidential balance (an `EncryptedAmount` plus a count of merged u16-bounded values that bounds limb growth) — and the linear coins that move value in/out of it, `PublicCoin<T>` and `EncryptedCoin<T>`. All are `phantom`-parameterized by the token type, mirroring `sui::balance::Balance<T>` / `sui::coin::Coin<T>`, so different token types can't be mixed. The balance has only `store` (no `copy`/`drop`) and is mutated in place: split (`try_split_to_public` / `try_split_batch`), merge (`merge_public` / `merge_encrypted` / `merge`), verified re-state (`try_update` / `set_public_key`), and `TreasuryCap`-gated issuer overrides (`overwrite_unchecked` / `clear_unchecked`). `try_split_batch` splits receiver-keyed `EncryptedCoin`s off the balance: the transfer total's commitment is reconstructed from the receiver amounts (the sender and receiver commitments are identical), its single sender-keyed decryption handle (`total_handle`) is supplied by the caller and proven well-formed by an ElGamal consistency proof, and a DDH balance proof shows the balance drops by exactly that total. The sender therefore never sends per-limb sender-keyed handles.
- **twisted_elgamal.move**: On-chain `Encryption` type (ciphertext + decryption handle), homomorphic add/sub, consistency verification.
- **nizk.move**: Fiat-Shamir NIZKs over Ristretto255 — `DdhProof` (shared-witness DDH over a vector of base/image pairs: the classic Chaum-Pedersen tuple is the two-pair case, used for balance/equality proofs; key rotation is the five-pair case, one `w` re-keying the public key and all four limb decryption handles at once) and `ElGamalProof` (witness-folded twisted ElGamal well-formedness over any number of same-key ciphertexts at a constant `2` points + `2` scalars; a single ciphertext is the batch-of-1 case), plus `KeyConsistencyProof` (auditor viewing-key encryption). All verifiers reduce to two shared Schnorr row-checkers and bind the statement bases into the Blake2b256 challenge transcript, so the same proof types are reusable across different DDH/ElGamal/key-encryption contexts.
- **deny_list.move**: Sui DenyList integration for per-address freezing and global pause (KYC/compliance).

### TypeScript SDK (`ts-sdk/src/`)
Client-side cryptographic operations and transaction building, mirroring the Move modules.

- **client.ts**: `ContraClient` -- builds Move call transactions for register, wrap, unwrap, transfer, and account management.
- **token_account.ts**: Client-side representation of a user's token account state. Includes `decryptWithProof(ciphertext, table)` for the selective-disclosure flow: given any `Ciphertext` (e.g. a collapsed balance or a `TransferEvent`'s encrypted amount), it returns `{ value, proof }` -- a plaintext and a zero-knowledge proof of correct decryption verifiable with `ciphertext.verifyDecryption(pk, value, proof)`. Also `recoverSentAmount(encryptedAmount, point, batchIndex, table)` for a sender to recover its own outgoing batched-transfer amounts: the sender stores no per-transfer secret and instead re-derives the per-limb blindings from `seed = HKDF(sk * point)` (the `TransferEvent`'s `transfer_randomness_point`) and reads the value off the commitments (which equal the receiver's), with no sender-keyed decryption handle.
- **twisted_elgamal.ts**: Key generation, encryption/decryption (`decrypt` via handle + `decryptWithBlinding` from a known blinding for the sender-recovery path), precomputed discrete log table for fast brute-force decryption.
- **transfer_randomness.ts**: Per-transfer randomness for batched transfers. `sampleTransferRandomness(senderPk)` draws one scalar `t`, exposes the point `P = t*G` (sent on chain) and seed-derived per-(recipient, limb) blindings from `seed = HKDF(t*senderPk)`; `recoverTransferRandomness(sk, P)` reproduces the same blindings from `sk * P`. Client-only KDF (HKDF-SHA256), never recomputed on chain.
- **pedersen.ts**: Pedersen commitment creation and verification.
- **nizk.ts**: NIZK proof generation/verification mirroring `nizk.move` — `DdhNizk` (shared-witness DDH over base/image pairs; two-pair balance/equality case, five-pair re-key case) and `ElGamalNizk` (witness-folded batch over same-key ciphertexts at constant size; `helpers.ts`'s `buildWellFormedProof` folds each amount's four limbs into one proof), plus `KeyConsistencyProof`.
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
- `@mysten/sui` for Sui SDK integration
- Sui Move 2024 edition standard library
