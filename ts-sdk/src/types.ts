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
	/** The auditor's twisted ElGamal private key (the secret for the token's current auditor pk). */
	privateKey: PrivateKey;
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
	 * The account's optional default key — the key `register_permissionless` uses when a third party
	 * auto-registers a token for this account. Omit it to create the account without one (no third
	 * party can then auto-register tokens for it). Per-token keys are chosen independently at
	 * `register` and are not tied to this key. The account is created for the transaction sender, so
	 * the transaction must be signed by the intended owner.
	 */
	defaultKey?: RistrettoPoint;
}

/** The key a single token's balances are currently encrypted under (see `ContraClient.getTokenKeys`). */
export interface TokenKeyStatus {
	/** The fully-qualified Move token type. */
	tokenType: string;
	/** Whether a `TokenAccount<T>` is registered for this token under the account. */
	registered: boolean;
	/** The key this token's balances are currently under, or `undefined` when not registered. */
	publicKey?: RistrettoPoint;
	/**
	 * True when the token's key differs from the account's default key (`Account.pk`), computed only
	 * when that key is set. Since `rotateKeys` sets the default key to the convergence target, a
	 * stale token is one that has not caught up: it still needs `rekeyToken`, and its balance can only
	 * be re-keyed or decrypted with the key it currently reports here. While any token reports an old
	 * key, that old private key must be retained.
	 */
	stale: boolean;
}

/** Result of `ContraClient.getTokenKeys`: the account's default key plus each queried token's key. */
export interface AccountTokenKeys {
	/** The account's optional default key (`Account.pk`), or `undefined` when unset. */
	accountPublicKey?: RistrettoPoint;
	/** One entry per queried token type, in the same order. */
	tokens: TokenKeyStatus[];
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

/** Arguments to `ContraClient.registerPermissionless`. */
export interface RegisterPermissionlessOptions {
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
	 * The current auditor public key, or `undefined` when auditing is disabled. When set, transfers
	 * must attach per-transfer auditor data readable under this key.
	 */
	currentPk?: RistrettoPoint;
	/**
	 * The previous auditor public key retained across a rotation, or `undefined`. Transfers built
	 * against it stay valid through `previousExpirationEpoch`.
	 */
	previousPk?: RistrettoPoint;
	/** The last epoch (inclusive) at which `previousPk` still audits in-flight transfers. */
	previousExpirationEpoch: bigint;
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

/** Arguments to `ContraClient.setDefaultKey`. */
export interface SetDefaultKeyOptions {
	/**
	 * A token account for the owner whose default key is being set. Only its `address` and `tokenType`
	 * are used (the latter to type the `Auth<T>` and the Move call).
	 */
	tokenAccount: TokenAccount;
	/**
	 * The new default key for the account (used by `register_permissionless`). Pass `null` (or omit)
	 * to clear it, disabling permissionless auto-registration. Per-token keys are unaffected.
	 */
	newDefaultKey?: RistrettoPoint | null;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an `as_sender` auth. The resulting
	 * `Auth<T>` must cover the `REGISTER` operation.
	 */
	auth?: AuthThunk;
}

/** Arguments to `ContraClient.rekeyToken` / `tryRekeyToken`. */
export interface RekeyTokenOptions {
	/** The token account carrying the token's current (old) key — its balance is re-keyed from here. */
	tokenAccount: TokenAccount;
	/**
	 * The post-rotation token account, carrying the new key. Must have the same `address` and
	 * `tokenType` as `tokenAccount`, and its public key must equal the account key already set by
	 * `setDefaultKey`. The caller persists it to decrypt the re-keyed balance.
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

/**
 * Arguments to `ContraClient.rotateKeys`: set the account's default key once and optimistically re-key
 * one or more tokens to that new key in one PTB.
 */
export interface RotateKeysOptions {
	/**
	 * The current token accounts to re-key — each carries its own `tokenType` and current key, so
	 * tokens under different keys can be mixed. Must all be for the same account (same `address`).
	 */
	tokenAccounts: readonly TokenAccount[];
	/**
	 * A `TokenAccount` carrying the new key that every token converges to (also set as the account's
	 * default key). Only its key and address are used; its `tokenType` is ignored.
	 */
	newTokenAccount: TokenAccount;
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
