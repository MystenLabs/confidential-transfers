// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ClientWithCoreApi } from '@mysten/sui/client';
import type { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import type { RistrettoPoint } from './ristretto255.js';
import type { TokenAccount } from './token_account.js';
import type {
	DiscreteLogTable,
	EncryptedAmount,
	MultiRecipientEncryption,
	PrivateKey,
} from './twisted_elgamal.js';

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

/**
 * Parsed form of the on-chain `auditors::VerifiedKeyEncryption` Move struct: the per-limb
 * `MultiRecipientEncryption` ciphertexts of the user's private key under the auditor pks of
 * `version`. Shape shared by `TokenAccount<T>.verified_key_encryption` and the
 * `verified_key_encryption` field on `NewRegistrationEvent<T>` / `UpdatedPublicKeyEvent<T>`.
 */
export interface VerifiedKeyEncryption {
	ciphertext: MultiRecipientEncryption[];
	version: number;
}

/** This auditor's index in, and secret key for, one on-chain auditor key version. */
export type AuditorVersionEntry = {
	/** This auditor's index in the auditor `pks` list of the given version. */
	index: number;
	/** This auditor's twisted ElGamal private key for that version. */
	privateKey: PrivateKey;
};

/** Options for constructing a `ContraAuditor`. */
export interface ContraAuditorOptions {
	suiClient: ContraCompatibleClient;
	/** Addresses of the contra Move package and its shared registries. */
	packageConfig: ContraPackageConfig;
	/** The fully-qualified Move type of the token this auditor is scoped to, e.g. `0x2::sui::SUI`. */
	tokenType: string;
	/**
	 * Precomputed discrete-log table used for decryption. The auditor
	 * encryption is over u32 limbs, so the standard `numBits = 16` table
	 * (which covers 2^32) is sufficient; a larger table speeds up the
	 * key-recovery path at the cost of more memory.
	 */
	table: DiscreteLogTable;
	/**
	 * Map version → (index, sk). Versions where this auditor was not in
	 * the auditor set should be omitted (no record). Expected to cover
	 * every on-chain version this auditor was part of, up to the
	 * current one.
	 */
	auditorKeyForVersion: Map<number, AuditorVersionEntry>;
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
	/** The address that will own the newly created account. */
	owner: string;
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
	 * When the confidential token has auditors configured, pass their
	 * public keys here. The client will encrypt the token account's
	 * private key to each auditor key and generate a `KeyConsistencyProof`,
	 * which are required by `contra::register` when auditors are set.
	 */
	auditorPublicKeys?: RistrettoPoint[];
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an
	 * `as_sender` auth.
	 */
	auth?: AuthThunk;
}

/** Return value of `ContraClient.getAccountStatus`. */
export interface AccountStatus {
	/**
	 * `true` if the account is frozen for the given token type. A frozen account cannot
	 * wrap, transfer, receive, or unwrap until the issuer unfreezes it.
	 */
	isFrozen: boolean;
}

/** Return value of `ContraClient.getAuditors`. */
export interface TokenAuditors {
	/** The auditor public keys registered for this token. Empty when no auditors are configured. */
	pks: RistrettoPoint[];
	/** Incremented each time `update_auditors` is called. */
	version: number;
	/**
	 * Issuer-advertised minimum viewing-key encryption `version`. Not enforced on chain;
	 * wallets should treat accounts whose `keyEncryptionVersion` is below this as stale
	 * and prompt the user to rotate before transferring.
	 */
	recommendedMinVersion: number;
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

/** Arguments to `ContraClient.rotateKeyAndUnpauseAccount`. */
export interface RotateKeyOptions {
	/** The token account whose encryption key is being rotated. */
	tokenAccount: TokenAccount;
	/**
	 * The post-rotation token account, carrying the new private key. Must have the
	 * same `address` and `tokenType` as `tokenAccount`. The caller persists this so
	 * it can decrypt the post-rotation balance and authorize future operations.
	 */
	newTokenAccount: TokenAccount;
	/**
	 * When `true` (the default), the rotation PTB pauses encrypted deposits and merges
	 * pending deposits before the optimistic rekey, so the whole flow is self-contained.
	 * Set to `false` when the account is already paused and merged (e.g. paused in a prior
	 * transaction): the client asserts the account is paused and skips the pause + merge,
	 * issuing only the rekey.
	 */
	pauseAndMerge?: boolean;
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an `as_sender` auth.
	 * The thunk is invoked once per consumed `Auth<T>` site within the same PTB.
	 * The resulting `Auth<T>` must cover the `REGISTER` operation.
	 */
	auth?: AuthThunk;
}

/** Arguments to `ContraClient.rotateKeyAndTransferBatch`. */
export interface RotateKeyAndTransferBatchOptions {
	/** The sender's token account, whose encryption key is being rotated. */
	tokenAccount: TokenAccount;
	/**
	 * The post-rotation token account, carrying the new private key. Must have the same
	 * `address` and `tokenType` as `tokenAccount`. The caller persists it; the transfer is
	 * built against the post-rotation balance under its key.
	 */
	newTokenAccount: TokenAccount;
	/** The recipients of the batch, same shape and `[1, 7]` limit as `transferBatch`. */
	recipients: readonly BatchedTransferRecipient[];
	/**
	 * Optional `Auth<T>` builder. When omitted, the client builds an `as_sender` auth. Invoked
	 * once per consumed `Auth<T>` site; the result must cover both the `REGISTER` operation (for
	 * the rotation) and the sender's transfer.
	 */
	auth?: AuthThunk;
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
