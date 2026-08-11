// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ClientWithCoreApi } from '@mysten/sui/client';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import type { RistrettoPoint } from './ristretto255.js';
import type { TokenAccount } from './token_account.js';
import type { DiscreteLogTable, EncryptedAmount, PrivateKey } from './twisted_elgamal.js';

/** Arguments to `ContraClient.wrap`. */
export interface WrapOptions {
	/**
	 * The public coin to wrap. The coin is consumed. Either a bare
	 * object ID (for a coin that already exists on chain) or a
	 * `TransactionObjectArgument` for a coin produced earlier in the
	 * same transaction (e.g. via `tx.splitCoins`).
	 */
	coin: TransactionObjectArgument | string;
	/**
	 * The owner address of the account that will receive the wrapped
	 * amount in its pending encrypted balance.
	 */
	receiver: string;
	/**
	 * The fully-qualified Move type of the token being wrapped, e.g.
	 * `0x2::sui::SUI`.
	 */
	tokenType: string;
	/** Optional memo attached to the wrap event; omit or empty for no memo. */
	memo?: string;
	/**
	 * If `true`, and `receiver` has an `Account` with a `default_pk` but no `TokenAccount<T>` yet,
	 * register one for them (under their `default_pk`) in the same PTB before wrapping. Only works for
	 * tokens with permissionless registration. When `false` (the default), `receiver` must already be
	 * registered — otherwise `wrap` throws `TokenAccountDoesNotExistError`.
	 */
	registerReceiver?: boolean;
}

/**
 * A single encrypted balance component surfaced by `getBalance`: the
 * on-chain ciphertext together with its
 * decrypted plaintext `amount`.
 */
export interface BalanceEntry {
	/** The on-chain encrypted amount as four `Ciphertext` limbs. */
	ciphertext: EncryptedAmount;
	/**
	 * The decrypted value as a `bigint`.
	 */
	amount: bigint;
	/**
	 * The upper bound for the balance limbs: `limb_i <= balanceUpperBound * 2^16`.
	 */
	upperBound: number;
}

/**
 * Result of `ContraClient.getBalance`. The active and encrypted-deposit
 * components are returned as `BalanceEntry` pairs so callers can see
 * both the on-chain ciphertexts and the decrypted plaintexts; the
 * public deposit component is stored in plaintext on chain and is
 * returned as a bare `bigint`.
 */
export interface TokenBalance {
	/** The active (spendable) balance. */
	balance: BalanceEntry;
	/**
	 * Pending encrypted deposits received from other confidential
	 * accounts. Not yet merged into `balance`.
	 */
	pending: BalanceEntry;
	/**
	 * Pending public deposits (wrapped from public coins). Stored on
	 * chain in plaintext so no ciphertext is returned. Not yet merged
	 * into `balance`.
	 */
	pendingPublicBalance: bigint;
}

/**
 * A Sui client that has been extended with the `core` API. Any client
 * returned by `new SuiGrpcClient(...)` satisfies this constraint.
 */
export type ContraCompatibleClient = ClientWithCoreApi;

/**
 * Configuration describing where the `contra` Move package has been
 * published and the shared registry objects that were created on init.
 */
export interface ContraPackageConfig {
	/** The object ID of the published `contra` Move package. */
	packageId: string;
	/** The shared account registry object ID. */
	accountRegistryId: string;
	/** The shared token registry object ID. */
	tokenRegistryId: string;
}

export interface ContraClientOptions {
	suiClient: ContraCompatibleClient;
	/** Addresses of the contra Move package and its shared registries. */
	packageConfig: ContraPackageConfig;
	/** Precomputed discrete-log table for decryption. */
	table: DiscreteLogTable;
	/**
	 * Optional explicit URL/bytes for the bulletproofs `.wasm` asset, forwarded
	 * to `getBulletproofs()`. Needed only in browser environments where the
	 * bundler can't locate the asset automatically; Node ignores it.
	 */
	wasmUrl?: string | URL | Request | BufferSource;
}

/** Options for constructing a `ContraAuditor`. */
export interface ContraAuditorOptions {
	/** The fully-qualified Move type of the token this auditor is scoped to, e.g. `0x2::sui::SUI`. */
	tokenType: string;
	/**
	 * The auditor's twisted ElGamal private key(s). Provide every key the auditor has held — the
	 * current one plus any rotated-out keys — so transfers made before a rotation, which stay
	 * encrypted under an old key, still decrypt; `decryptTransferAmount` matches the transfer's
	 * `auditor_pk` to the right key. More can be added later with `ContraAuditor.addKey`.
	 */
	privateKeys: PrivateKey[];
	/**
	 * Precomputed discrete-log table used for decryption. The per-transfer auditor encryption is
	 * over u32 limbs, so the standard `numBits = 16` table (which covers 2^32) is sufficient.
	 */
	table: DiscreteLogTable;
}

export interface ContraOptions {
	/** Addresses of the contra Move package and its shared registries. */
	packageConfig: ContraPackageConfig;
	/** Precomputed discrete-log table for decryption. */
	table: DiscreteLogTable;
	/**
	 * Optional explicit URL/bytes for the bulletproofs `.wasm` asset, forwarded
	 * to `getBulletproofs()`. Needed only in browser environments where the
	 * bundler can't locate the asset automatically; Node ignores it.
	 */
	wasmUrl?: string | URL | Request | BufferSource;
}

/** Arguments to `ContraClient.transfer`. */
/**
 * Auth-builder thunk for `transfer` / `unwrap` etc. The SDK calls it once
 * per consumption site within the same PTB.
 */
export type AuthThunk = (tx: Transaction) => TransactionObjectArgument;

export interface TransferOptions {
	/** The sender's token account. */
	tokenAccount: TokenAccount;
	/** The receiver's address. */
	receiverAddress: string;
	/** The amount to transfer. */
	amount: bigint;
	/** Optional memo attached to the transfer event; omit or empty for no memo. */
	memo?: string;
	/**
	 * When `true` (the default), pending deposits are merged into the
	 * active balance before the transfer if any exist. Set to `false`
	 * to skip the merge and transfer from the active balance only.
	 */
	merge?: boolean;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an
	 * `as_sender` auth.
	 */
	auth?: AuthThunk;
	/**
	 * If `true`, any receiver that has an `Account` with a `default_pk` but no `TokenAccount<T>` yet
	 * is registered (under their `default_pk`) in the same PTB before the transfer. Only works for
	 * tokens with permissionless registration. When `false` (the default), every receiver must
	 * already be registered — otherwise the transfer throws `TokenAccountDoesNotExistError`.
	 */
	registerReceiver?: boolean;
}

/** A single (receiver, amount, memo) entry in a batched transfer. */
export interface BatchedTransferRecipient {
	/** The receiver's address. */
	receiverAddress: string;
	/** The amount to transfer to this receiver. */
	amount: bigint;
	/** Optional memo attached to this recipient's `TransferEvent`; omit or empty for no memo. */
	memo?: string;
}

/** Arguments to `ContraClient.transferBatch`. */
export interface BatchedTransferOptions {
	/** The sender's token account. */
	tokenAccount: TokenAccount;
	/**
	 * The recipients of the batch. Each entry produces one `TransferEvent` on
	 * chain. The order is preserved end-to-end: `recipients[i]` is credited to
	 * `recipients[i].receiverAddress` with `recipients[i].memo`.
	 *
	 * Length must be in `[1, 7]`: Move can verify at most 8 aggregated
	 * bulletproof range proofs in a single call, and one slot is consumed by
	 * the sender's new-balance proof.
	 */
	recipients: readonly BatchedTransferRecipient[];
	/**
	 * When `true` (the default), pending deposits are merged into the
	 * active balance before the transfer if any exist. Set to `false`
	 * to skip the merge and transfer from the active balance only.
	 */
	merge?: boolean;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an
	 * `as_sender` auth.
	 */
	auth?: AuthThunk;
	/**
	 * If `true`, any receiver that has an `Account` with a `default_pk` but no `TokenAccount<T>` yet
	 * is registered (under their `default_pk`) in the same PTB before the transfer. Only works for
	 * tokens with permissionless registration. When `false` (the default), every receiver must
	 * already be registered — otherwise the transfer throws `TokenAccountDoesNotExistError`.
	 */
	registerReceiver?: boolean;
}

/** Arguments to `ContraClient.unwrap`. */
export interface UnwrapOptions {
	/** The token account to unwrap from. */
	tokenAccount: TokenAccount;
	/** The amount to unwrap back into a public coin. */
	amount: bigint;
	/**
	 * When `true` (the default), pending deposits are merged into the
	 * active balance before the unwrap if any exist. Set to `false`
	 * to skip the merge and unwrap from the active balance only.
	 */
	merge?: boolean;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an
	 * `as_sender` auth.
	 */
	auth?: AuthThunk;
}

/** Arguments to `ContraClient.updateBalance`. */
export interface UpdateBalanceOptions {
	/** The token account to update. */
	tokenAccount: TokenAccount;
	/**
	 * When `true` (the default), pending deposits are merged into the
	 * active balance before updating. Set to `false` to skip the merge
	 * and re-normalize the active balance only.
	 */
	merge?: boolean;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an
	 * `as_sender` auth.
	 */
	auth?: AuthThunk;
}

/** Arguments to `ContraClient.newAccount`. */
export interface NewAccountOptions {
	/**
	 * The owner address the account is created for. Creation is permissionless — anyone can create
	 * the account for any owner; it only reserves the owner's derived slot and sets no key. Set a
	 * default key afterwards with `setDefaultPkAsSender` if others should be able to auto-register
	 * tokens for it via `register_with_default_pk`.
	 */
	owner: string;
}

/**
 * One token's key status, as reported by `ContraClient.getTokenKeys` (one per queried token type, in
 * the same order).
 */
export interface TokenKeyStatus {
	/** The fully-qualified Move token type. */
	tokenType: string;
	/** Whether a `TokenAccount<T>` is registered for this token under the account. */
	registered: boolean;
	/** The key this token's balances are currently under, or `undefined` when not registered. */
	publicKey?: RistrettoPoint;
}

/** Arguments to `ContraClient.register`. */
export interface RegisterOptions {
	/** The token account holding address, tokenType, and private key. */
	tokenAccount: TokenAccount;
	/**
	 * Optional account object argument for use in the same PTB as
	 * `newAccount`. When omitted, the account is looked up on-chain by
	 * its derived ID.
	 */
	account?: TransactionObjectArgument;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an
	 * `as_sender` auth.
	 */
	auth?: AuthThunk;
}

/** Arguments to `ContraClient.tryRegisterWithDefaultPk`. */
export interface RegisterWithDefaultPkOptions {
	/** The owner address of the account to register a token account for. Must already have an `Account`. */
	receiver: string;
	/** The fully-qualified Move type of the token to register, e.g. `0x2::sui::SUI`. */
	tokenType: string;
}

/** Return value of `ContraClient.getAccountStatus`. */
export interface AccountStatus {
	/**
	 * `true` if the account is frozen for the given token type. A frozen account cannot
	 * wrap, transfer, receive, or unwrap until the issuer unfreezes it.
	 */
	isFrozen: boolean;
}

/** Return value of `ContraClient.getAuditor`: the token's per-transfer auditor configuration. */
export interface TokenAuditor {
	/**
	 * The current auditor public keys (one per auditor); empty when auditing is disabled. When
	 * non-empty, transfers must attach one per-transfer auditor-readable ciphertext set per key. (The
	 * rotation grace window — the `previous_pks` set — is enforced on chain, so it is not surfaced here.)
	 */
	currentPks: RistrettoPoint[];
}

/** Arguments to `ContraClient.pauseAccount`. */
export interface PauseAccountOptions {
	/** The token account that should stop accepting new encrypted deposits. */
	tokenAccount: TokenAccount;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an `as_sender` auth.
	 * Any `Auth<T>` that authenticates `tokenAccount.address` is accepted -- the
	 * Move side does not require a specific operation flag here.
	 */
	auth?: AuthThunk;
}

/** Arguments to `ContraClient.unpauseAccount`. */
export interface UnpauseAccountOptions {
	/** The token account that should resume accepting new encrypted deposits. */
	tokenAccount: TokenAccount;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an `as_sender` auth.
	 * Any `Auth<T>` that authenticates `tokenAccount.address` is accepted -- the
	 * Move side does not require a specific operation flag here.
	 */
	auth?: AuthThunk;
}

/** Arguments to `ContraClient.setDefaultPkAsSender`. */
export interface SetDefaultPkAsSenderOptions {
	/**
	 * The owner address of the account whose default key is being set. The transaction must be signed
	 * by this address (only the owner can set it).
	 */
	account: string;
	/**
	 * The new default key for the account (used by `register_with_default_pk`). Pass `null` (or omit)
	 * to clear it, disabling permissionless auto-registration. Per-token keys are unaffected.
	 */
	defaultPk?: RistrettoPoint | null;
}

/** Arguments to `ContraClient.rekeyTokenAccount` / `tryRekeyTokenAccount`. */
export interface RekeyTokenAccountOptions {
	/** The token account carrying the token's current (old) key — its balance is re-keyed from here. */
	tokenAccount: TokenAccount;
	/**
	 * The post-rotation token account, carrying the new key. Must have the same `address` and
	 * `tokenType` as `tokenAccount`; its public key is chosen independently of the account's default
	 * key. The caller persists it to decrypt the re-keyed balance.
	 */
	newTokenAccount: TokenAccount;
	/**
	 * When `true` (the default) and the token has pending deposits, a `merge` is prepended so the
	 * re-key (which requires an empty pending balance) can proceed against the merged active balance.
	 */
	merge?: boolean;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an `as_sender` auth. The resulting
	 * `Auth<T>` must cover the `REGISTER` operation.
	 */
	auth?: AuthThunk;
}

/** A single re-key in `ContraClient.tryRekeyTokenAccounts`: the token's current account and its new one. */
export interface KeyRotation {
	/** The token's current account — its `address`, `tokenType`, and current key. */
	tokenAccount: TokenAccount;
	/**
	 * A `TokenAccount` carrying the new key this token re-keys to (must hold the new private key, of
	 * the same `tokenType`). Different rotations may use different new keys.
	 */
	newTokenAccount: TokenAccount;
}

/**
 * Arguments to `ContraClient.tryRekeyTokenAccounts`: optimistically re-key one or more tokens in one PTB, each
 * to its own new key (the batched, soft-failing plural of `tryRekeyTokenAccount`).
 */
export interface TryRekeyTokenAccountsOptions {
	/**
	 * The tokens to re-key, as (current, new) pairs. Each token re-keys from its `tokenAccount`'s key
	 * to the paired `newTokenAccount`'s key; different tokens may go to different keys. All accounts
	 * must be for the same account (same `address`).
	 */
	rotations: readonly KeyRotation[];
	/**
	 * When `true` (the default), a `merge` is prepended before each token's re-key so it can proceed
	 * against the merged active balance (re-key requires an empty pending balance).
	 */
	merge?: boolean;
}

/** Arguments to `ContraClient.shareAccount`. */
export interface ShareAccountOptions {
	/**
	 * The account to share. Typically the `TransactionObjectArgument`
	 * returned from a preceding `newAccount` call in the same
	 * transaction.
	 */
	account: TransactionObjectArgument;
}
