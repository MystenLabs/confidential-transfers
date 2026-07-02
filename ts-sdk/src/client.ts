// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { bcs } from '@mysten/sui/bcs';
import type {
	Transaction,
	TransactionObjectArgument,
	TransactionResult,
} from '@mysten/sui/transactions';
import { deriveObjectID, normalizeSuiAddress } from '@mysten/sui/utils';
import { ristretto255 } from '@noble/curves/ed25519.js';

import { getBulletproofs, type BatchRangeProver, type Bulletproofs } from './bp.js';
import * as contraContracts from './contracts/contra/contra.js';
import { Field as DynamicField } from './contracts/sui/dynamic_field.js';
import {
	DepositsMustBePausedError,
	InsufficientBalanceError,
	InvalidArgumentError,
	ReceiverDoesNotAcceptDepositsError,
	TokenAccountDoesNotExistError,
} from './error.js';
import {
	buildBatchedDdhProof,
	buildDdhProof,
	buildElGamalProof,
	buildEncryptedAmount,
	buildEncryptedAmountAndProof,
	buildGVector,
	buildKeyEncryptionOption,
	buildWellFormedProof,
	getAccountId,
	getConfidentialTokenId,
	getTokenAccountId,
	point,
	PROTOCOL_BATCH_DDH,
	PROTOCOL_DDH,
	PROTOCOL_ELGAMAL,
	PROTOCOL_KEY_CONSISTENCY,
	PROTOCOL_RANGE_PROOF_16,
	PROTOCOL_RANGE_PROOF_32,
	type WellFormedLimb,
} from './helpers.js';
import { KeyEncryption } from './key_encryption.js';
import { BatchedDdhNizk, DdhTupleNizk, ElGamalNizk } from './nizk.js';
import { addScalars, mul, pointFromBcs, randomScalar } from './ristretto255.js';
import { TokenAccount } from './token_account.js';
import { sampleTransferRandomness } from './transfer_randomness.js';
import type { DiscreteLogTable, PublicKey } from './twisted_elgamal.js';
import { Ciphertext, collapseBlindings, EncryptedAmount } from './twisted_elgamal.js';
import type {
	AccountStatus,
	BatchedTransferOptions,
	ContraClientOptions,
	ContraCompatibleClient,
	ContraOptions,
	ContraPackageConfig,
	NewAccountOptions,
	PauseAccountOptions,
	RegisterOptions,
	RotateKeyAndTransferBatchOptions,
	RotateKeyOptions,
	ShareAccountOptions,
	TokenAuditors,
	TokenBalance,
	TransferOptions,
	UnpauseAccountOptions,
	UnwrapOptions,
	UpdateBalanceOptions,
	WrapOptions,
} from './types.js';

/**
 * Create a contra client extension that can be registered with a Sui
 * client, e.g. `suiClient.$extend(contra({ packageConfig, table }))`.
 * `table` is a precomputed `DiscreteLogTable` used to brute-force decrypt
 * limb-sized ciphertexts.
 */
export function contra(options: ContraOptions) {
	return {
		name: 'contra' as const,
		register: (client: ContraCompatibleClient) => {
			return new ContraClient({
				suiClient: client,
				...options,
			});
		},
	};
}

/**
 * Stateless client for the `contra` Move package.
 *
 * Each transaction-building method returns a thunk
 * `(tx: Transaction) => TransactionResult` that can be passed to
 * `tx.add(...)`. Methods that need encryption key material take a
 * `TokenAccount` directly — the client holds no per-account state.
 */
export class ContraClient {
	#suiClient: ContraCompatibleClient;
	#packageConfig: ContraPackageConfig; // Will be static per network in the future.
	#table: DiscreteLogTable;
	#wasmUrl?: string | URL | Request | BufferSource;
	#bulletproofs?: Promise<Bulletproofs>;

	constructor(options: ContraClientOptions) {
		this.#suiClient = options.suiClient;
		this.#packageConfig = options.packageConfig;
		this.#table = options.table;
		this.#wasmUrl = options.wasmUrl;
	}

	/**
	 * Lazily initialize and cache the bulletproofs WASM bindings. The cached
	 * promise means `getBulletproofs()` (and the underlying WASM init) runs at
	 * most once per client. Awaited by each proof-building method during its
	 * async phase, so the returned synchronous functions are safe to call from
	 * the (synchronous) PTB thunks those methods return.
	 */
	#getBulletproofs(): Promise<Bulletproofs> {
		this.#bulletproofs ??= getBulletproofs(this.#wasmUrl);
		return this.#bulletproofs;
	}

	/** Return the shared confidential token object ID for the given token type. */
	#getConfidentialTokenId(tokenType: string): string {
		return getConfidentialTokenId(this.#packageConfig, tokenType);
	}

	/** Return the shared pool object ID for the given token type. */
	#getPoolId(tokenType: string): string {
		return deriveObjectID(
			this.#getConfidentialTokenId(tokenType),
			`${this.#packageConfig.packageId}::contra::PoolKey`,
			bcs.byteVector().serialize([]).toBytes(),
		);
	}

	async #getAccountState(address: string, tokenType: string): Promise<AccountState> {
		const [state] = await this.#getAccountStates([address], tokenType);
		return state;
	}

	/**
	 * Multi-get version of `#getAccountState`. Issues a single
	 * `core.getObjects` RPC for all addresses, preserving order. Throws if any
	 * underlying object fetch returned an `Error` entry.
	 */
	async #getAccountStates(
		addresses: readonly string[],
		tokenType: string,
	): Promise<AccountState[]> {
		const objectIds = addresses.map((a) => this.getTokenAccountId(a, tokenType));

		// TODO: consider exposing a function that receives the objects from the caller,
		// so that the caller could fetch them differently.
		const { objects } = await this.#suiClient.core.getObjects({
			objectIds,
			include: { content: true },
		});

		return objects.map((object, i) => {
			if (object instanceof Error) {
				throw new TokenAccountDoesNotExistError(addresses[i], object.message);
			}
			const parsed = TokenAccountField.parse(object.content).value;
			return {
				pk: pointFromBcs(parsed.pk),
				acceptsEncryptedDeposits: parsed.accepts_deposits,
				isFrozen: parsed.is_frozen,
				keyEncryptionVersion: parsed.verified_key_encryption.version,
			};
		});
	}

	/** Return the account object ID for the given owner address. */
	getAccountId(address: string): string {
		return getAccountId(this.#packageConfig, address);
	}

	/**
	 * Return the object ID of the token account for the given
	 * `tokenType` inside the account owned by `address`.
	 */
	getTokenAccountId(address: string, tokenType: string): string {
		return getTokenAccountId(this.#packageConfig, address, tokenType);
	}

	/**
	 * Create a new account for the given owner.
	 *
	 * @example
	 * ```ts
	 * const tx = new Transaction();
	 * const account = tx.add(contraClient.newAccount({ owner: senderAddress }));
	 * tx.add(contraClient.shareAccount({ account }));
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAccountAlreadyRegistered` — `owner` already has an account (one per address).
	 */
	newAccount({ owner }: NewAccountOptions) {
		return contraContracts.newAccount({
			package: this.#packageConfig.packageId,
			arguments: { registry: this.#packageConfig.accountRegistryId, owner },
		});
	}

	/**
	 * Share an account object. The account is consumed by value, so the
	 * argument must be a freshly-created account (e.g. the result of
	 * `newAccount`) that has not yet been shared.
	 */
	shareAccount({ account }: ShareAccountOptions) {
		return contraContracts.shareAccount({
			package: this.#packageConfig.packageId,
			arguments: { account },
		});
	}

	/**
	 * Fetch the on-chain token account and return its full balance state
	 * as a `TokenBalance`: the active (spendable) balance, the pending
	 * encrypted deposits, and the pending public deposits.
	 *
	 * @example
	 * ```ts
	 * const { balance, pending, pendingPublicBalance } =
	 *   await contraClient.getBalance(tokenAccount);
	 * ```
	 *
	 * Throws `TokenAccountDoesNotExistError` if `tokenAccount.address` is not
	 * registered for `tokenAccount.tokenType`.
	 */
	async getBalance(tokenAccount: TokenAccount): Promise<TokenBalance> {
		const sk = tokenAccount.privateKey;
		const tokenAccountId = this.getTokenAccountId(tokenAccount.address, tokenAccount.tokenType);

		// TODO: consider exposing a function that receives the object from the caller,
		// so that the caller could fetch it differently.
		const {
			objects: [object],
		} = await this.#suiClient.core.getObjects({
			objectIds: [tokenAccountId],
			include: { content: true },
		});
		if (object instanceof Error) {
			throw new TokenAccountDoesNotExistError(tokenAccount.address, object.message);
		}

		const parsed = TokenAccountField.parse(object.content).value;
		const balanceCiphertext = EncryptedAmount.fromBcs(parsed.active.amount);
		const pendingCiphertext = EncryptedAmount.fromBcs(parsed.pending.amount);

		return {
			balance: {
				ciphertext: balanceCiphertext,
				amount: balanceCiphertext.decrypt(sk, this.#table),
				upperBound: parsed.active.upper_bound,
			},
			pending: {
				ciphertext: pendingCiphertext,
				amount: pendingCiphertext.decrypt(sk, this.#table),
				upperBound: parsed.pending.upper_bound,
			},
			// `public_balance` is a `PublicCoin` — its `value` is the pending public deposit total.
			pendingPublicBalance: BigInt(parsed.public_balance.value),
		};
	}

	/**
	 * Fetch the on-chain public key for a given address and token type.
	 *
	 * @example
	 * ```ts
	 * const pk = await contraClient.getPublicKey(
	 *   recipientAddress,
	 *   '0x2::sui::SUI',
	 * );
	 * ```
	 *
	 * Throws `TokenAccountDoesNotExistError` if `address` is not registered for
	 * `tokenType`.
	 */
	async getPublicKey(address: string, tokenType: string): Promise<PublicKey> {
		return (await this.#getAccountState(address, tokenType)).pk;
	}

	/**
	 * Fetch the current auditor configuration for the given token type.
	 *
	 * Returns the auditor public keys together with the current version number
	 * and the `recommendedMinVersion` floor. The floor is advisory: the chain
	 * does not enforce it, but wallets should treat accounts whose
	 * viewing-key encryption version is below it as stale and prompt the user
	 * to rotate via `set_public_key` before transferring.
	 *
	 * @example
	 * ```ts
	 * const { pks, version, recommendedMinVersion } =
	 *   await contraClient.getAuditors('0x2::sui::SUI');
	 * ```
	 *
	 * Throws the underlying fetch error if any.
	 */
	async getAuditors(tokenType: string): Promise<TokenAuditors> {
		const { auditors } = await this.#getConfidentialToken(tokenType);
		return {
			pks: auditors.pks.map((e) => pointFromBcs(e)),
			version: auditors.version,
			recommendedMinVersion: auditors.recommended_min_version,
		};
	}

	/**
	 * Fetch and parse the on-chain `ConfidentialToken<T>` object. Used to read
	 * `is_active` (global freeze) and the auditor set; the auditor exposure goes
	 * through `getAuditors`.
	 */
	async #getConfidentialToken(tokenType: string) {
		const { object } = await this.#suiClient.core.getObject({
			objectId: this.#getConfidentialTokenId(tokenType),
			include: { content: true },
		});
		return contraContracts.ConfidentialToken.parse(object.content);
	}

	/**
	 * Return `true` iff the token is globally frozen. When frozen, no account can wrap,
	 * transfer, or unwrap until the issuer calls `global_unfreeze`.
	 *
	 * @example
	 * ```ts
	 * if (await contraClient.isTokenFrozen('0x2::sui::SUI')) {
	 *   // Surface to the user; building a transfer/unwrap would just abort on chain.
	 * }
	 * ```
	 *
	 * Throws the underlying fetch error if any.
	 */
	async isTokenFrozen(tokenType: string): Promise<boolean> {
		return !(await this.#getConfidentialToken(tokenType)).is_active;
	}

	/**
	 * Fetch the on-chain status of a per-token account.
	 *
	 * Currently exposes whether the account is frozen via `isFrozen`. A frozen
	 * account cannot wrap, transfer, receive, or unwrap for this token type
	 * until the issuer unfreezes it.
	 *
	 * @example
	 * ```ts
	 * const { isFrozen } = await contraClient.getAccountStatus(
	 *   userAddress,
	 *   '0x2::sui::SUI',
	 * );
	 * ```
	 *
	 * Throws `TokenAccountDoesNotExistError` if `address` is not registered for
	 * `tokenType`.
	 */
	async getAccountStatus(address: string, tokenType: string): Promise<AccountStatus> {
		return { isFrozen: (await this.#getAccountState(address, tokenType)).isFrozen };
	}

	/**
	 * Return `true` iff the issuer's `recommendedMinVersion` is above this account's
	 * `keyEncryptionVersion`, signalling that the user should refresh their on-chain
	 * key encryption against the new auditor set.
	 *
	 * @example
	 * ```ts
	 * if (await contraClient.shouldRotateKey(tokenAccount)) {
	 *   // Caller builds the post-rotation account and submits the PTB themselves.
	 *   // See `rotateKeyAndUnpauseAccount` for the full pause→rotate flow.
	 * }
	 * ```
	 *
	 * Throws `TokenAccountDoesNotExistError` if `tokenAccount.address` is not
	 * registered for `tokenAccount.tokenType`.
	 */
	async shouldRotateKey(tokenAccount: TokenAccount): Promise<boolean> {
		const [auditors, state] = await Promise.all([
			this.getAuditors(tokenAccount.tokenType),
			this.#getAccountState(tokenAccount.address, tokenAccount.tokenType),
		]);
		return state.keyEncryptionVersion < auditors.recommendedMinVersion;
	}

	/**
	 * Register a token account for `tokenAccount.tokenType` inside the
	 * account owned by `tokenAccount.address`.
	 *
	 * The public key registered on chain is derived from the token
	 * account's private key as `G * privateKey`.
	 *
	 * When `account` is omitted the shared account object is looked up
	 * by its derived ID. Pass `account` explicitly when the account was
	 * just created in the same PTB and is not yet shared on chain.
	 *
	 * @example
	 * ```ts
	 * // Standalone registration (account already shared on chain):
	 * const tx = new Transaction();
	 * tx.add(await contraClient.register({ tokenAccount }));
	 *
	 * // In the same PTB as account creation:
	 * const tx = new Transaction();
	 * const account = tx.add(contraClient.newAccount({ owner: senderAddress }));
	 * tx.add(await contraClient.register({ tokenAccount, account }));
	 * tx.add(contraClient.shareAccount({ account }));
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAccountAlreadyRegistered` — the account is already registered for `T`.
	 * - `EAuthorizationError` — `auth` was invalid.
	 * - `EMissingEncryptedViewingKeyArguments` / `ETooManyEncryptedViewingKeyArguments` —
	 *   `auditorPublicKeys` doesn't match the token's auditor configuration (omitted
	 *   when required, or provided when the token has none).
	 * - `EInvalidEncryptedViewingKey` — `auditorPublicKeys` doesn't match the on-chain
	 *   auditor set.
	 */
	async register({
		tokenAccount,
		account,
		auditorPublicKeys,
		auth,
	}: RegisterOptions): Promise<(tx: Transaction) => TransactionResult> {
		const { address, tokenType } = tokenAccount;
		const pkBytes = tokenAccount.publicKey.toBytes();
		const pid = this.#packageConfig.packageId;

		const { batchRangeProver } = await this.#getBulletproofs();
		const keyEncryption =
			auditorPublicKeys && auditorPublicKeys.length > 0
				? KeyEncryption.prove(
						batchRangeProver,
						tokenAccount.dst(PROTOCOL_KEY_CONSISTENCY),
						tokenAccount.dst(PROTOCOL_RANGE_PROOF_32),
						tokenAccount.privateKey,
						tokenAccount.publicKey,
						auditorPublicKeys,
					)
				: undefined;

		return (tx: Transaction): TransactionResult =>
			tx.add(
				contraContracts.register({
					package: pid,
					typeArguments: [tokenType],
					arguments: {
						ct: this.#getConfidentialTokenId(tokenType),
						account: account ?? this.getAccountId(address),
						auth: auth ? auth(tx) : this.#asSenderAuth(tx, tokenType),
						pk: point(pkBytes),
						keyEncryption: buildKeyEncryptionOption(pid, keyEncryption),
					},
				}),
			);
	}

	/**
	 * Wrap a public coin into the receiver's pending encrypted balance.
	 *
	 * The supplied coin is consumed, its value is added to the pool for
	 * that token, and the same amount is credited to the receiver's
	 * pending public balance. The receiver's account must already be
	 * shared on chain.
	 *
	 * @example
	 * ```ts
	 * const tx = new Transaction();
	 * const [payment] = tx.splitCoins(tx.object(sourceCoinId), [10n]);
	 * tx.add(
	 *   contraClient.wrap({
	 *     coin: payment,
	 *     receiver: receiverAddress,
	 *     tokenType: '0x2::sui::SUI',
	 *   }),
	 * );
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `ETransferDenied` — the token is paused, the deny list is globally frozen, the receiver
	 *   is on the deny list, or the receiver's per-account freeze is active.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — `receiver` is not registered for the token.
	 */
	wrap({ coin, receiver, tokenType, memo }: WrapOptions) {
		return (tx: Transaction): TransactionResult =>
			tx.add(
				contraContracts.wrap({
					package: this.#packageConfig.packageId,
					typeArguments: [tokenType],
					arguments: {
						receiver: this.getAccountId(receiver),
						auth: this.#asSenderAuth(tx, tokenType),
						ct: this.#getConfidentialTokenId(tokenType),
						pool: this.#getPoolId(tokenType),
						coin: typeof coin === 'string' ? tx.object(coin) : coin,
						memo: memoBytes(memo),
					},
				}),
			);
	}

	/**
	 * Fetch the on-chain balance, optionally include pending deposits,
	 * and return the new encrypted balance limbs together with the old
	 * (collapsed) balance ciphertext needed to build a balance proof.
	 */
	async #createBalanceUpdate(
		tokenAccount: TokenAccount,
		amount: bigint,
		merge: boolean,
		diff: Ciphertext,
	): Promise<{
		shouldMerge: boolean;
		newBalance: WellFormedLimb[];
		balanceProof: DdhTupleNizk;
	}> {
		// TODO: consider exposing a function that receives the object from the caller,
		// so that the caller could fetch it differently.
		const { balance, pending, pendingPublicBalance } = await this.getBalance(tokenAccount);

		const hasPendingDeposits = pending.amount > 0n || pendingPublicBalance > 0n;
		const shouldMerge = merge && hasPendingDeposits;

		const spendable = shouldMerge
			? balance.amount + pending.amount + pendingPublicBalance
			: balance.amount;

		if (amount > spendable) {
			throw new InsufficientBalanceError(amount, spendable, shouldMerge ? 'total' : 'active');
		}

		const oldBalance = shouldMerge
			? balance.ciphertext
					.collapse()
					.add(pending.ciphertext.collapse())
					.add(Ciphertext.trivial(pendingPublicBalance))
			: balance.ciphertext.collapse();

		const pk = tokenAccount.publicKey;
		const elgamalDst = tokenAccount.dst(PROTOCOL_ELGAMAL);
		const ddhDst = tokenAccount.dst(PROTOCOL_DDH);
		const newBalance = intoLimbs(spendable - amount).map((v) => ({
			value: v,
			...Ciphertext.encryptWithConsistencyProof(elgamalDst, pk, v, randomScalar()),
		}));

		const balanceProof = new EncryptedAmount(
			newBalance[0].ciphertext,
			newBalance[1].ciphertext,
			newBalance[2].ciphertext,
			newBalance[3].ciphertext,
		)
			.collapse()
			.subtract(oldBalance)
			.add(diff)
			.proveIsZero(ddhDst, tokenAccount.privateKey, pk);

		return { shouldMerge, newBalance, balanceProof };
	}

	/**
	 * Merge all pending deposits (both encrypted and public) into the active
	 * balance. Internal: external callers should set `merge: true` on
	 * `transfer` / `unwrap` / `updateBalance` and let those prepend the merge
	 * call with the `auth` they already minted.
	 */
	#merge({ tokenAccount, auth }: { tokenAccount: TokenAccount; auth: TransactionObjectArgument }) {
		return (tx: Transaction): TransactionResult =>
			tx.add(
				contraContracts.merge({
					package: this.#packageConfig.packageId,
					typeArguments: [tokenAccount.tokenType],
					arguments: {
						account: this.getAccountId(tokenAccount.address),
						auth,
					},
				}),
			);
	}

	/**
	 * Re-normalize the active balance into its canonical limb form.
	 *
	 * When `merge` is `true` (the default) and the sender has pending
	 * deposits, a `merge` call is prepended to the
	 * transaction so that pending deposits are included in the updated
	 * balance.
	 *
	 * Should be called in rare cases where the balance was modified by
	 * ~2^16 merges.
	 *
	 * @example
	 * ```ts
	 * const normalize = await client.contra.updateBalance({ tokenAccount });
	 * const tx = new Transaction();
	 * tx.add(normalize);
	 * ```
	 *
	 * SDK-thrown:
	 * - `TokenAccountDoesNotExistError` — the token account couldn't be fetched.
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — `tokenAccount.address` isn't registered for the token.
	 * - `EBalanceProofFailed` — the balance changed between fetch and submission (e.g. a
	 *   merge with `merge=false`, or a public deposit landing in between).
	 */
	async updateBalance({
		tokenAccount,
		merge = true,
		auth,
	}: UpdateBalanceOptions): Promise<(tx: Transaction) => TransactionResult> {
		const { batchRangeProver } = await this.#getBulletproofs();
		const { shouldMerge, newBalance, balanceProof } = await this.#createBalanceUpdate(
			tokenAccount,
			0n,
			merge,
			Ciphertext.trivial(0n),
		);

		return (tx: Transaction): TransactionResult => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenAccount.tokenType);
			if (shouldMerge) {
				tx.add(this.#merge({ tokenAccount, auth: authArg }));
			}
			return this.#updateActiveBalance(
				batchRangeProver,
				tx,
				tokenAccount,
				newBalance,
				balanceProof,
				authArg,
			);
		};
	}

	/**
	 * Helper composing `buildEncryptedAmountAndProof` + `buildDdhProof` with the
	 * generated `contra::update_active_balance` Move call for `tokenAccount`.
	 * Reused by `updateBalance` and the rotate-key flow.
	 */
	#updateActiveBalance(
		batchRangeProver: BatchRangeProver,
		tx: Transaction,
		tokenAccount: TokenAccount,
		newBalance: WellFormedLimb[],
		balanceProof: DdhTupleNizk,
		auth: TransactionObjectArgument,
	): TransactionResult {
		const pid = this.#packageConfig.packageId;
		const { encryptedAmount, wellFormedProof } = buildEncryptedAmountAndProof(
			batchRangeProver,
			tokenAccount.dst(PROTOCOL_RANGE_PROOF_16),
			tx,
			pid,
			newBalance,
		);
		return tx.add(
			contraContracts.updateActiveBalance({
				package: pid,
				typeArguments: [tokenAccount.tokenType],
				arguments: {
					account: this.getAccountId(tokenAccount.address),
					auth,
					newBalance: encryptedAmount,
					newBalanceProof: wellFormedProof,
					balanceProof: buildDdhProof(pid, balanceProof),
				},
			}),
		);
	}

	/**
	 * Pause new encrypted deposits to `tokenAccount`. Subsequent `transfer` /
	 * `transferBatch` calls targeting this account abort on the receiver-side
	 * `add_to_batch` step (the sender-side balance is not consumed). Required
	 * before `rotateKeyAndUnpauseAccount`; the rotation PTB unpauses deposits at the end.
	 *
	 * @example
	 * ```ts
	 * const pauseFn = contraClient.pauseAccount({ tokenAccount });
	 * const tx = new Transaction();
	 * tx.add(pauseFn);
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — `tokenAccount.address` is not registered for the token.
	 */
	pauseAccount({
		tokenAccount,
		auth,
	}: PauseAccountOptions): (tx: Transaction) => TransactionResult {
		return (tx: Transaction) =>
			this.#setAcceptsEncryptedDeposits(
				tx,
				tokenAccount,
				false,
				auth ? auth(tx) : this.#asSenderAuth(tx, tokenAccount.tokenType),
			);
	}

	/**
	 * Unpause encrypted deposits to `tokenAccount` after a `pauseAccount`. Note that
	 * the rotation PTB already unpauses on its own, so this is only needed for callers
	 * that paused for some other reason (or want to recover from a failed rotation).
	 *
	 * @example
	 * ```ts
	 * const unpauseFn = contraClient.unpauseAccount({ tokenAccount });
	 * const tx = new Transaction();
	 * tx.add(unpauseFn);
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — `tokenAccount.address` is not registered for the token.
	 */
	unpauseAccount({
		tokenAccount,
		auth,
	}: UnpauseAccountOptions): (tx: Transaction) => TransactionResult {
		return (tx: Transaction) =>
			this.#setAcceptsEncryptedDeposits(
				tx,
				tokenAccount,
				true,
				auth ? auth(tx) : this.#asSenderAuth(tx, tokenAccount.tokenType),
			);
	}

	/**
	 * Add a `contra::set_accepts_encrypted_deposits` Move call toggling whether `tokenAccount`
	 * accepts new encrypted deposits.
	 */
	#setAcceptsEncryptedDeposits(
		tx: Transaction,
		tokenAccount: TokenAccount,
		accepts: boolean,
		auth: TransactionObjectArgument,
	): TransactionResult {
		return tx.add(
			contraContracts.setAcceptsEncryptedDeposits({
				package: this.#packageConfig.packageId,
				typeArguments: [tokenAccount.tokenType],
				arguments: {
					account: this.getAccountId(tokenAccount.address),
					auth,
					acceptsEncryptedDeposits: accepts,
				},
			}),
		);
	}

	/**
	 * Rotate a token account's encryption key. The caller supplies the post-rotation
	 * `newTokenAccount` and must persist it.
	 *
	 * By default (`pauseAndMerge = true`) the returned PTB is optimistic and self-contained: it
	 * pauses encrypted deposits, folds any pending deposits into the active balance, then in one
	 * `try_set_public_key_and_unpause` call re-states the balance under a fresh blinding, re-keys
	 * it, and unpauses. The pause and merge always commit. If a new encrypted deposit lands between
	 * the SDK's balance read and execution, the restate's balance proof no longer matches:
	 * `try_set_public_key_and_unpause` no-ops (emitting `TrySetPublicKeyFailedEvent`) and the
	 * account is left paused with the merge applied. Re-run `rotateKeyAndUnpauseAccount` against the
	 * new balance to converge — no deposit can race the retry since the account is now paused.
	 *
	 * Pass `pauseAndMerge = false` when the account is already paused and merged (e.g. paused in a
	 * prior transaction): the PTB skips the pause + merge and issues only the rekey. The account
	 * must already refuse deposits or this throws `DepositsMustBePausedError`.
	 *
	 * Detect success/failure via the emitted events: `UpdatedPublicKeyEvent` on success,
	 * `TrySetPublicKeyFailedEvent` on a raced retry.
	 *
	 * SDK-thrown:
	 * - `DepositsMustBePausedError` — `pauseAndMerge` is `false` but the account still accepts
	 *   encrypted deposits.
	 * - `InvalidArgumentError` — `pauseAndMerge` is `false` but the account has pending deposits
	 *   that must be merged first.
	 * - `TokenAccountDoesNotExistError` — `tokenAccount` is not registered for the
	 *   token.
	 *
	 * On-chain aborts (rare; mostly indicate races with concurrent admin actions):
	 * - `EAuthorizationError` — `auth` was not for the owner.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — account lost its registration between SDK and execution.
	 * - `EMissingEncryptedViewingKeyArguments` / `ETooManyEncryptedViewingKeyArguments` /
	 *   `EInvalidEncryptedViewingKey` — the auditor set changed between the SDK's
	 *   read and execution.
	 *
	 * @example
	 * ```ts
	 * const newTokenAccount = new TokenAccount(address, tokenType, packageConfig, randomScalar());
	 * const rotateFn = await contraClient.rotateKeyAndUnpauseAccount({ tokenAccount, newTokenAccount });
	 * const tx = new Transaction();
	 * tx.add(rotateFn);
	 * ```
	 */
	async rotateKeyAndUnpauseAccount({
		tokenAccount,
		newTokenAccount,
		pauseAndMerge = true,
		auth,
	}: RotateKeyOptions): Promise<(tx: Transaction) => TransactionResult> {
		const { address, tokenType } = tokenAccount;
		const oldPk = tokenAccount.publicKey;
		const oldSk = tokenAccount.privateKey;
		const newSk = newTokenAccount.privateKey;
		const newPk = newTokenAccount.publicKey;

		if (
			!pauseAndMerge &&
			(await this.#getAccountState(address, tokenType)).acceptsEncryptedDeposits
		) {
			throw new DepositsMustBePausedError(address);
		}

		// `verify_key_encryption` runs against the live `Auditors` value, so the only
		// auditor set that can produce a valid `KeyEncryption` is the one currently on
		// chain. An empty `pks` array means the token has no auditors and no key
		// encryption is attached.
		const auditorPks = (await this.getAuditors(tokenType)).pks;
		const useAuditors = auditorPks.length > 0;

		const { balance, pending, pendingPublicBalance } = await this.getBalance(tokenAccount);
		const hasPending = pending.amount > 0n || pendingPublicBalance > 0n;
		if (hasPending && !pauseAndMerge) {
			throw new InvalidArgumentError(`Cannot skip pause and merge when there are pending deposits`);
		}

		const totalSpendable = hasPending
			? balance.amount + pending.amount + pendingPublicBalance
			: balance.amount;

		const oldCollapsed = hasPending
			? balance.ciphertext
					.collapse()
					.add(pending.ciphertext.collapse())
					.add(Ciphertext.trivial(pendingPublicBalance))
			: balance.ciphertext.collapse();

		const elgamalDst = tokenAccount.dst(PROTOCOL_ELGAMAL);
		const ddhDst = tokenAccount.dst(PROTOCOL_DDH);

		// Per-limb encryption of the spendable amount under the OLD public key with
		// fresh blindings we know. After `update_active_balance` lands, these become the
		// on-chain commitments and decryption handles.
		const newBalanceUnderOldPk = intoLimbs(totalSpendable).map((value) => ({
			value,
			...Ciphertext.encryptWithConsistencyProof(elgamalDst, oldPk, value, randomScalar()),
		}));

		// Balance proof for `update_active_balance`: collapsed(new) - collapsed(old) == 0.
		const balanceProofUpdate = new EncryptedAmount(
			newBalanceUnderOldPk[0].ciphertext,
			newBalanceUnderOldPk[1].ciphertext,
			newBalanceUnderOldPk[2].ciphertext,
			newBalanceUnderOldPk[3].ciphertext,
		)
			.collapse()
			.subtract(oldCollapsed)
			.proveIsZero(ddhDst, oldSk, oldPk);

		// Batched re-key (Π_rekey): the witness `w = newSk * oldSk^{-1}` maps each old handle to the new
		// one (`w * D_i = r_i*newPk`) using only the secret keys; commitments are reused, so no proof.
		const w = ristretto255.Point.Fn.create(newSk * ristretto255.Point.Fn.inv(oldSk));
		const newBalanceUnderNewPk = newBalanceUnderOldPk.map((l) => ({
			ciphertext: new Ciphertext(l.ciphertext.ciphertext, mul(l.ciphertext.decryptionHandle, w)),
		}));
		const rekeyBases = [oldPk, ...newBalanceUnderOldPk.map((l) => l.ciphertext.decryptionHandle)];
		const rekeyImages = [newPk, ...newBalanceUnderNewPk.map((l) => l.ciphertext.decryptionHandle)];
		const rekeyProof = BatchedDdhNizk.prove(
			tokenAccount.dst(PROTOCOL_BATCH_DDH),
			w,
			rekeyBases,
			rekeyImages,
		);

		const { batchRangeProver } = await this.#getBulletproofs();
		const keyEncryption = useAuditors
			? KeyEncryption.prove(
					batchRangeProver,
					tokenAccount.dst(PROTOCOL_KEY_CONSISTENCY),
					tokenAccount.dst(PROTOCOL_RANGE_PROOF_32),
					newSk,
					newPk,
					auditorPks,
				)
			: undefined;

		return (tx: Transaction): TransactionResult => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenType);
			const pid = this.#packageConfig.packageId;

			if (pauseAndMerge) {
				this.#setAcceptsEncryptedDeposits(tx, tokenAccount, false, authArg);
				tx.add(this.#merge({ tokenAccount, auth: authArg }));
			}

			const { encryptedAmount: restatedBalance, wellFormedProof: restatedBalanceProof } =
				buildEncryptedAmountAndProof(
					batchRangeProver,
					tokenAccount.dst(PROTOCOL_RANGE_PROOF_16),
					tx,
					pid,
					newBalanceUnderOldPk,
				);
			const newHandles = tx.add(
				buildGVector(
					pid,
					newBalanceUnderNewPk.map((l) => l.ciphertext.decryptionHandle),
				),
			);
			return tx.add(
				contraContracts.trySetPublicKeyAndUnpause({
					package: pid,
					typeArguments: [tokenType],
					arguments: {
						account: this.getAccountId(address),
						auth: authArg,
						ct: this.#getConfidentialTokenId(tokenType),
						newPk: point(newPk.toBytes()),
						restatedBalance,
						restatedBalanceProof,
						balanceProof: buildDdhProof(pid, balanceProofUpdate),
						newHandles,
						rekeyProof: buildBatchedDdhProof(pid, rekeyProof),
						keyEncryption: buildKeyEncryptionOption(pid, keyEncryption),
					},
				}),
			);
		};
	}

	/**
	 * Build a confidential transfer transaction.
	 *
	 * Convenience wrapper around `transferBatch` for the single-recipient case.
	 * See `transferBatch` for the full semantics.
	 *
	 * @example
	 * ```ts
	 * const transferFn = await contraClient.transfer({
	 *   tokenAccount: senderTokenAccount,
	 *   receiverAddress,
	 *   amount: 100n,
	 * });
	 * const tx = new Transaction();
	 * tx.add(transferFn);
	 * ```
	 *
	 * See `transferBatch` for the full list of SDK-thrown errors and on-chain aborts.
	 */
	async transfer({
		tokenAccount,
		receiverAddress,
		amount,
		memo,
		merge = true,
		auth,
	}: TransferOptions): Promise<(tx: Transaction) => TransactionResult> {
		return this.transferBatch({
			tokenAccount,
			recipients: [{ receiverAddress, amount, memo }],
			merge,
			auth,
		});
	}

	/**
	 * Build a confidential batched transfer transaction.
	 *
	 * Fetches the sender's current balance and each receiver's on-chain public
	 * key, encrypts each transfer amount under both keys, generates the
	 * required zero-knowledge proofs, and returns a thunk that adds the
	 * `contra::batched_transfer` flow.
	 *
	 * The `recipients` order is preserved end-to-end: `recipients[i]` is
	 * credited to `recipients[i].receiverAddress` with `recipients[i].memo`,
	 * matching the order of emitted `TransferEvent`s.
	 *
	 * `recipients.length` must be in `[1, 7]`.
	 *
	 * When `merge` is `true` (the default) and the sender has pending
	 * deposits, a `merge` call is prepended to the transaction so that
	 * pending deposits are included in the spendable balance. The proofs are
	 * computed against the post-merge balance.
	 *
	 * Note: when `merge` is enabled, the transaction may succeed but only
	 * the merge is executed, not the transfers themselves. This happens if
	 * the sender receives a deposit after the balance is fetched but before
	 * the transaction is submitted. In that case, a `TryTransferFailedEvent`
	 * is emitted and no receiver is credited (the on-chain `BalanceProofFailed`
	 * branch short-circuits every `add_to_batch`). You can either try again or
	 * call `transferBatch` with `merge = false` to be sure that the
	 * transaction succeeds.
	 *
	 * @example
	 * ```ts
	 * const transferFn = await contraClient.transferBatch({
	 *   tokenAccount: senderTokenAccount,
	 *   recipients: [
	 *     { receiverAddress: alice, amount: 100n },
	 *     { receiverAddress: bob, amount: 50n, memo: 'rent' },
	 *   ],
	 * });
	 * const tx = new Transaction();
	 * tx.add(transferFn);
	 * ```
	 *
	 * SDK-thrown:
	 * - `InvalidArgumentError` — `recipients` is empty, has more than 255 entries, or
	 *   contains the sender's own address.
	 * - `ReceiverDoesNotAcceptDepositsError` — at least one receiver has paused encrypted
	 *   deposits or has a per-account freeze active.
	 * - `InsufficientBalanceError` — total amount exceeds the spendable balance (active,
	 *   or active + pending when `merge` is `true`).
	 * - `TokenAccountDoesNotExistError` — sender or a receiver is not registered for the
	 *   token (no on-chain `TokenAccount` object).
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `ETransferDenied` — the token is paused, the deny list is globally frozen, the sender
	 *   or a receiver is on the deny list, the sender has a per-account freeze active (the
	 *   receiver-frozen case is caught by the SDK), or a receiver's state changed between the
	 *   SDK check and execution.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — sender or receiver lost its registration between the
	 *   SDK's check and execution.
	 */
	async transferBatch({
		tokenAccount,
		recipients,
		merge = true,
		auth,
	}: BatchedTransferOptions): Promise<(tx: Transaction) => TransactionResult> {
		if (recipients.length === 0 || recipients.length > MAX_BATCH_RECIPIENTS) {
			throw new InvalidArgumentError(
				`Batch size must be in [1, ${MAX_BATCH_RECIPIENTS}], got ${recipients.length}.`,
			);
		}
		const { address: senderAddress, tokenType } = tokenAccount;
		const senderPk = tokenAccount.publicKey;
		const elgamalDst = tokenAccount.dst(PROTOCOL_ELGAMAL);

		const normalizedSender = normalizeSuiAddress(senderAddress);
		if (recipients.some((r) => normalizeSuiAddress(r.receiverAddress) === normalizedSender)) {
			throw new InvalidArgumentError(`Cannot transfer to yourself (${senderAddress}).`);
		}

		// Fetch every receiver's state in a single multi-get RPC. Surface every
		// receiver that can't accept encrypted deposits in one error, rather
		// than failing on the first.
		const receiverStates = await this.#getAccountStates(
			recipients.map((r) => r.receiverAddress),
			tokenType,
		);
		const refusing = recipients
			.map((recipient, i) => ({ recipient, state: receiverStates[i] }))
			.filter(({ state }) => !state.acceptsEncryptedDeposits || state.isFrozen)
			.map(({ recipient }) => recipient.receiverAddress);
		if (refusing.length > 0) {
			throw new ReceiverDoesNotAcceptDepositsError(refusing);
		}

		// Per-transfer randomness: a single point `P` plus seed-derived per-(recipient, limb)
		// blindings. `P` is published in each `TransferEvent` so the sender can re-derive these
		// blindings later (`seed = HKDF(sk * P)`) and recover its outgoing amounts from the
		// commitments alone — no sender-keyed decryption handles are sent.
		const randomness = sampleTransferRandomness(senderPk);

		// Each transfer amount under its receiver's key, with the seed-derived blindings and a
		// `WellFormedProof` (range + consistency), bound to the sender's ELGAMAL DST. No sender-keyed
		// amount is sent — its commitments equal the receiver's, which the chain sums for the transfer
		// total (see `try_split_batch`); `add_to_batch` checks each coin's pk against the receiver.
		const prepared = recipients.map((recipient, i) => {
			const receiverPk = receiverStates[i].pk;
			const encAmountReceiver = intoLimbs(recipient.amount).map((value, j) => ({
				value,
				...Ciphertext.encryptWithConsistencyProof(
					elgamalDst,
					receiverPk,
					value,
					randomness.blinding(i, j),
				),
			}));
			return { recipient, receiverPk, encAmountReceiver };
		});

		// The total transferred amount and its collapsed blinding, across all recipients.
		const totalAmount = recipients.reduce((acc, r) => acc + r.amount, 0n);
		const totalBlinding = addScalars(prepared.map((p) => collapseBlindings(p.encAmountReceiver)));
		// The total re-encrypted under the sender's key: its commitment is the sum of the receiver
		// commitments (key-independent), its handle is `senderPk * totalBlinding`. Only the handle is
		// sent on chain (`totalSenderHandle`); the `consistencyProof` proves it is the honest one — pinning
		// the amount the balance proof debits.
		const { ciphertext: totalSenderEnc } = Ciphertext.encryptWithBlinding(
			senderPk,
			totalAmount,
			totalBlinding,
		);
		const consistencyProof = ElGamalNizk.prove(
			elgamalDst,
			totalBlinding,
			totalAmount,
			totalSenderEnc,
			senderPk,
		);

		const { shouldMerge, newBalance, balanceProof } = await this.#createBalanceUpdate(
			tokenAccount,
			totalAmount,
			merge,
			totalSenderEnc,
		);

		const { batchRangeProver } = await this.#getBulletproofs();

		return (tx: Transaction): TransactionResult => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenType);
			if (shouldMerge) {
				tx.add(this.#merge({ tokenAccount, auth: authArg }));
			}

			const pid = this.#packageConfig.packageId;

			// One aggregate `WellFormedProof` covers every receiver amount AND the sender's new
			// balance, in that order (new_balance last). Bound to the sender's ELGAMAL DST;
			// `batched_transfer` verifies it under `[...receiver_pks, sender_pk]`, pops the
			// new_balance entry, and `add_to_batch` later asserts each coin's pk matches the
			// receiver it's credited to.
			// 1. Start the batched transfer: split the receiver-keyed coins off the sender's
			//    balance against the balance proof. One `well_formed_proofs` covers receivers
			//    and the new balance; `totalSenderHandle` is the single sender-keyed decryption handle
			//    for the transfer total, proven well-formed by `consistencyProof`;
			//    `seedPoint` (`P`) is forwarded to the events.
			let [batch] = tx.add(
				contraContracts.batchedTransfer({
					package: pid,
					typeArguments: [tokenType],
					arguments: {
						sender: this.getAccountId(senderAddress),
						auth: authArg,
						ct: this.#getConfidentialTokenId(tokenType),
						receiverPks: buildGVector(
							pid,
							prepared.map((p) => p.receiverPk),
						),
						receiverAmounts: tx.makeMoveVec({
							type: `${pid}::encrypted_amount::EncryptedAmount`,
							elements: prepared.map((p) =>
								buildEncryptedAmount(
									pid,
									p.encAmountReceiver.map((l) => l.ciphertext),
								),
							),
						}),
						wellFormedProofs: buildWellFormedProof(
							batchRangeProver,
							tokenAccount.dst(PROTOCOL_RANGE_PROOF_16),
							pid,
							[...prepared.map((p) => p.encAmountReceiver), newBalance],
						),
						totalSenderHandle: point(totalSenderEnc.decryptionHandle.toBytes()),
						consistencyProof: buildElGamalProof(pid, consistencyProof),
						seedPoint: point(randomness.seedPoint.toBytes()),
						newBalance: buildEncryptedAmount(
							pid,
							newBalance.map((l) => l.ciphertext),
						),
						balanceProof: buildDdhProof(pid, balanceProof),
					},
				}),
			);

			// 2. Add receivers in submission order. `add_to_batch` pops the next
			//    receiver-keyed coin and credits it: prepared[i] ↔ recipients[i].
			for (const p of prepared) {
				[batch] = tx.add(
					contraContracts.addToBatch({
						package: pid,
						typeArguments: [tokenType],
						arguments: {
							batch,
							receiver: this.getAccountId(p.recipient.receiverAddress),
							memo: memoBytes(p.recipient.memo),
						},
					}),
				);
			}

			// 3. Finalize optimistically: on a failed balance proof, emits
			//    TryTransferFailedEvent rather than aborting.
			return tx.add(
				contraContracts.tryFinalize({
					package: pid,
					typeArguments: [tokenType],
					arguments: { batch },
				}),
			);
		};
	}

	/**
	 * Transfer to a batch of recipients and rotate the account's encryption key, all in one
	 * transaction: pause → merge → transfer → rotate (re-key + unpause).
	 *
	 * The transfer is built under the CURRENT (old) key against the merged balance; the rotation
	 * then re-states the post-transfer balance and re-keys it. Both steps are optimistic: if a
	 * deposit races the balance read, `TryTransferFailedEvent` is emitted and neither the transfer
	 * nor the rotation took effect. Pause and merge stay committed, so the caller just retries
	 * (deterministic now, since the account is paused). On success the account ends debited by the
	 * transfer total, re-keyed, and unpaused.
	 *
	 * @example
	 * ```ts
	 * const newTokenAccount = new TokenAccount(address, tokenType, packageConfig, randomScalar());
	 * const fn = await contraClient.rotateKeyAndTransferBatch({
	 *   tokenAccount,
	 *   newTokenAccount,
	 *   recipients: [{ receiverAddress: alice, amount: 100n }],
	 * });
	 * const tx = new Transaction();
	 * tx.add(fn);
	 * ```
	 *
	 * SDK-thrown:
	 * - `InvalidArgumentError` — `recipients` is empty, has more than 255 entries, or contains the
	 *   sender's own address.
	 * - `ReceiverDoesNotAcceptDepositsError` — at least one receiver has paused encrypted deposits
	 *   or has a per-account freeze active.
	 * - `InsufficientBalanceError` — the transfer total exceeds the spendable balance.
	 * - `TokenAccountDoesNotExistError` — sender or a receiver is not registered for the token.
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `ETransferDenied` — the token is paused, the deny list is globally frozen, the sender or
	 *   a receiver is on the deny list, the sender has a per-account freeze active (the
	 *   receiver-frozen case is caught by the SDK), or a receiver's state changed between the
	 *   SDK check and execution.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — sender or receiver lost its registration between the SDK's check
	 *   and execution.
	 */
	async rotateKeyAndTransferBatch({
		tokenAccount,
		newTokenAccount,
		recipients,
		auth,
	}: RotateKeyAndTransferBatchOptions): Promise<(tx: Transaction) => TransactionResult> {
		if (recipients.length === 0 || recipients.length > MAX_BATCH_RECIPIENTS) {
			throw new InvalidArgumentError(
				`Batch size must be in [1, ${MAX_BATCH_RECIPIENTS}], got ${recipients.length}.`,
			);
		}
		const { address, tokenType } = tokenAccount;
		const oldPk = tokenAccount.publicKey;
		const oldSk = tokenAccount.privateKey;
		const newPk = newTokenAccount.publicKey;
		const newSk = newTokenAccount.privateKey;
		const elgamalDst = tokenAccount.dst(PROTOCOL_ELGAMAL);
		const ddhDst = tokenAccount.dst(PROTOCOL_DDH);

		const normalizedSender = normalizeSuiAddress(address);
		if (recipients.some((r) => normalizeSuiAddress(r.receiverAddress) === normalizedSender)) {
			throw new InvalidArgumentError(`Cannot transfer to yourself (${address}).`);
		}

		const auditorPks = (await this.getAuditors(tokenType)).pks;
		const useAuditors = auditorPks.length > 0;

		const receiverStates = await this.#getAccountStates(
			recipients.map((r) => r.receiverAddress),
			tokenType,
		);
		const refusing = recipients
			.map((recipient, i) => ({ recipient, state: receiverStates[i] }))
			.filter(({ state }) => !state.acceptsEncryptedDeposits || state.isFrozen)
			.map(({ recipient }) => recipient.receiverAddress);
		if (refusing.length > 0) {
			throw new ReceiverDoesNotAcceptDepositsError(refusing);
		}

		// The whole spendable balance is merged first; the transfer debits it under the old key,
		// then the rotation re-keys whatever is left.
		const { balance, pending, pendingPublicBalance } = await this.getBalance(tokenAccount);
		const total = balance.amount + pending.amount + pendingPublicBalance;
		const oldCollapsed = balance.ciphertext
			.collapse()
			.add(pending.ciphertext.collapse())
			.add(Ciphertext.trivial(pendingPublicBalance));

		// --- Transfer material, built under the OLD key against the merged balance. ---
		// Per-transfer randomness (point `P` + seed-derived blindings) under the OLD key; see the
		// equivalent block in `transferBatch` for the rationale.
		const randomness = sampleTransferRandomness(oldPk);
		const prepared = recipients.map((recipient, i) => {
			const receiverPk = receiverStates[i].pk;
			const encAmountReceiver = intoLimbs(recipient.amount).map((value, j) => ({
				value,
				...Ciphertext.encryptWithConsistencyProof(
					elgamalDst,
					receiverPk,
					value,
					randomness.blinding(i, j),
				),
			}));
			return { recipient, receiverPk, encAmountReceiver };
		});
		const totalAmount = recipients.reduce((acc, r) => acc + r.amount, 0n);
		if (totalAmount > total) {
			throw new InsufficientBalanceError(totalAmount, total, 'total');
		}
		const totalBlinding = addScalars(prepared.map((p) => collapseBlindings(p.encAmountReceiver)));
		const { ciphertext: totalSenderEnc } = Ciphertext.encryptWithBlinding(
			oldPk,
			totalAmount,
			totalBlinding,
		);
		const consistencyProof = ElGamalNizk.prove(
			elgamalDst,
			totalBlinding,
			totalAmount,
			totalSenderEnc,
			oldPk,
		);
		// Sender's post-transfer balance under the old key: `total - totalAmount`.
		const transferNewBalance = intoLimbs(total - totalAmount).map((value) => ({
			value,
			...Ciphertext.encryptWithConsistencyProof(elgamalDst, oldPk, value, randomScalar()),
		}));
		const transferNewBalanceEnc = new EncryptedAmount(
			transferNewBalance[0].ciphertext,
			transferNewBalance[1].ciphertext,
			transferNewBalance[2].ciphertext,
			transferNewBalance[3].ciphertext,
		);
		const transferBalanceProof = transferNewBalanceEnc
			.collapse()
			.subtract(oldCollapsed)
			.add(totalSenderEnc)
			.proveIsZero(ddhDst, oldSk, oldPk);

		// --- Rotation material: re-state the POST-transfer balance under the old key (fresh known
		// blinding), then re-key the same (value, blinding) to the new key. ---
		const postTransferCollapsed = transferNewBalanceEnc.collapse();
		const restateUnderOldPk = intoLimbs(total - totalAmount).map((value) => ({
			value,
			...Ciphertext.encryptWithConsistencyProof(elgamalDst, oldPk, value, randomScalar()),
		}));
		const restateProof = new EncryptedAmount(
			restateUnderOldPk[0].ciphertext,
			restateUnderOldPk[1].ciphertext,
			restateUnderOldPk[2].ciphertext,
			restateUnderOldPk[3].ciphertext,
		)
			.collapse()
			.subtract(postTransferCollapsed)
			.proveIsZero(ddhDst, oldSk, oldPk);
		// Batched re-key (Π_rekey): the witness `w = newSk * oldSk^{-1}` maps each old handle to the new
		// one (`w * D_i = r*newPk`) using only the secret keys; commitments are reused, so no proof.
		const w = ristretto255.Point.Fn.create(newSk * ristretto255.Point.Fn.inv(oldSk));
		const balanceUnderNewPk = restateUnderOldPk.map((l) => ({
			ciphertext: new Ciphertext(l.ciphertext.ciphertext, mul(l.ciphertext.decryptionHandle, w)),
		}));
		const rekeyBases = [oldPk, ...restateUnderOldPk.map((l) => l.ciphertext.decryptionHandle)];
		const rekeyImages = [newPk, ...balanceUnderNewPk.map((l) => l.ciphertext.decryptionHandle)];
		const rekeyProof = BatchedDdhNizk.prove(
			tokenAccount.dst(PROTOCOL_BATCH_DDH),
			w,
			rekeyBases,
			rekeyImages,
		);
		const { batchRangeProver } = await this.#getBulletproofs();
		const keyEncryption = useAuditors
			? KeyEncryption.prove(
					batchRangeProver,
					tokenAccount.dst(PROTOCOL_KEY_CONSISTENCY),
					tokenAccount.dst(PROTOCOL_RANGE_PROOF_32),
					newSk,
					newPk,
					auditorPks,
				)
			: undefined;

		return (tx: Transaction): TransactionResult => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenType);
			const pid = this.#packageConfig.packageId;

			// 1. pause, 2. merge — always, so a deposit that raced the balance read is folded in.
			// Then the transfer fails optimistically (rather than the rekey aborting on pending),
			// and pause + merge stay committed for a clean retry.
			this.#setAcceptsEncryptedDeposits(tx, tokenAccount, false, authArg);
			tx.add(this.#merge({ tokenAccount, auth: authArg }));

			// 3. transfer, built under the OLD key against the merged balance.
			let [batch] = tx.add(
				contraContracts.batchedTransfer({
					package: pid,
					typeArguments: [tokenType],
					arguments: {
						sender: this.getAccountId(address),
						auth: authArg,
						ct: this.#getConfidentialTokenId(tokenType),
						receiverPks: buildGVector(
							pid,
							prepared.map((p) => p.receiverPk),
						),
						receiverAmounts: tx.makeMoveVec({
							type: `${pid}::encrypted_amount::EncryptedAmount`,
							elements: prepared.map((p) =>
								buildEncryptedAmount(
									pid,
									p.encAmountReceiver.map((l) => l.ciphertext),
								),
							),
						}),
						wellFormedProofs: buildWellFormedProof(
							batchRangeProver,
							tokenAccount.dst(PROTOCOL_RANGE_PROOF_16),
							pid,
							[...prepared.map((p) => p.encAmountReceiver), transferNewBalance],
						),
						totalSenderHandle: point(totalSenderEnc.decryptionHandle.toBytes()),
						consistencyProof: buildElGamalProof(pid, consistencyProof),
						seedPoint: point(randomness.seedPoint.toBytes()),
						newBalance: buildEncryptedAmount(
							pid,
							transferNewBalance.map((l) => l.ciphertext),
						),
						balanceProof: buildDdhProof(pid, transferBalanceProof),
					},
				}),
			);
			for (const p of prepared) {
				[batch] = tx.add(
					contraContracts.addToBatch({
						package: pid,
						typeArguments: [tokenType],
						arguments: {
							batch,
							receiver: this.getAccountId(p.recipient.receiverAddress),
							memo: memoBytes(p.recipient.memo),
						},
					}),
				);
			}
			tx.add(
				contraContracts.tryFinalize({
					package: pid,
					typeArguments: [tokenType],
					arguments: { batch },
				}),
			);

			// 4. rotate last: restate the post-transfer balance → re-key → unpause, optimistically.
			// If the transfer no-op'd on a race, the restate fails and this no-ops too — leaving the
			// account paused + merged so the caller just retries the transfer + rotation.
			const { encryptedAmount: restatedEa, wellFormedProof: restatedEaProof } =
				buildEncryptedAmountAndProof(
					batchRangeProver,
					tokenAccount.dst(PROTOCOL_RANGE_PROOF_16),
					tx,
					pid,
					restateUnderOldPk,
				);
			const newHandles = tx.add(
				buildGVector(
					pid,
					balanceUnderNewPk.map((l) => l.ciphertext.decryptionHandle),
				),
			);
			return tx.add(
				contraContracts.trySetPublicKeyAndUnpause({
					package: pid,
					typeArguments: [tokenType],
					arguments: {
						account: this.getAccountId(address),
						auth: authArg,
						ct: this.#getConfidentialTokenId(tokenType),
						newPk: point(newPk.toBytes()),
						restatedBalance: restatedEa,
						restatedBalanceProof: restatedEaProof,
						balanceProof: buildDdhProof(pid, restateProof),
						newHandles,
						rekeyProof: buildBatchedDdhProof(pid, rekeyProof),
						keyEncryption: buildKeyEncryptionOption(pid, keyEncryption),
					},
				}),
			);
		};
	}

	/**
	 * Unwrap an amount from the sender's confidential balance back into a
	 * public `Coin<T>`.
	 *
	 * When `merge` is `true` (the default) and the sender has pending
	 * deposits, a `merge` call is prepended to the
	 * transaction so that pending deposits are included in the spendable
	 * balance.
	 *
	 * Note: When `merge` is enabled, the transaction may succeed, but
	 * only the merge is actually executed, not the actual unwrap. This
	 * happens if the sender receives a deposit after the balance is
	 * fetched but before the transaction is submitted. In that case,
	 * a `TryUnwrapFailedEvent` is emitted and a zero-value coin is
	 * returned. You can either try again or call `unwrap` with
	 * `merge = false` to be sure that the unwrap succeeds.
	 *
	 * @example
	 * ```ts
	 * const unwrapFn = await contraClient.unwrap({ tokenAccount, amount: 100n });
	 * const tx = new Transaction();
	 * const coin = tx.add(unwrapFn);
	 * tx.transferObjects([coin], recipientAddress);
	 * ```
	 *
	 * SDK-thrown:
	 * - `InsufficientBalanceError` — `amount` exceeds the spendable balance (active, or
	 *   active + pending when `merge` is `true`).
	 * - `TokenAccountDoesNotExistError` — `tokenAccount.address` is not registered for
	 *   the token.
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `ETransferDenied` — the token is paused, the deny list is globally frozen, the sender is
	 *   on the deny list, or the account's per-account freeze is active.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — the account lost its registration between the SDK's check and
	 *   execution.
	 */
	async unwrap({
		tokenAccount,
		amount,
		merge = true,
		auth,
	}: UnwrapOptions): Promise<(tx: Transaction) => TransactionResult> {
		const { address, tokenType } = tokenAccount;

		const { batchRangeProver } = await this.#getBulletproofs();

		const { shouldMerge, newBalance, balanceProof } = await this.#createBalanceUpdate(
			tokenAccount,
			amount,
			merge,
			Ciphertext.trivial(amount),
		);

		return (tx: Transaction): TransactionResult => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenType);
			if (shouldMerge) {
				tx.add(this.#merge({ tokenAccount, auth: authArg }));
			}

			const pid = this.#packageConfig.packageId;
			const { encryptedAmount: newBalanceEa, wellFormedProof: newBalanceProof } =
				buildEncryptedAmountAndProof(
					batchRangeProver,
					tokenAccount.dst(PROTOCOL_RANGE_PROOF_16),
					tx,
					pid,
					newBalance,
				);
			return tx.add(
				contraContracts.tryUnwrap({
					package: pid,
					typeArguments: [tokenType],
					arguments: {
						account: this.getAccountId(address),
						auth: authArg,
						ct: this.#getConfidentialTokenId(tokenType),
						pool: this.#getPoolId(tokenType),
						newBalance: newBalanceEa,
						newBalanceProof,
						amount,
						balanceProof: buildDdhProof(pid, balanceProof),
					},
				}),
			);
		};
	}

	/**
	 * Create an `Auth<T>` for the transaction sender, covering every operation
	 * the policy on the confidential token leaves permissionless. Fails on chain if the policy
	 * gates the requested operation behind a witness.
	 */
	#asSenderAuth(tx: Transaction, tokenType: string): TransactionResult {
		return tx.add(
			contraContracts.authorizeAsSender({
				package: this.#packageConfig.packageId,
				typeArguments: [tokenType],
				arguments: { ct: this.#getConfidentialTokenId(tokenType) },
			}),
		);
	}
}

/**
 * Snapshot of the per-token state on a user's on-chain `TokenAccount<T>`,
 * decoded into the subset of fields the client needs to build transactions
 * and surface account status.
 */
interface AccountState {
	pk: PublicKey;
	acceptsEncryptedDeposits: boolean;
	isFrozen: boolean;
	keyEncryptionVersion: number;
}

/**
 * Max recipients in a single `transferBatch` PTB, bounded by the `u8` receiver index rather than
 * the range proof (which chunks any number of amounts). Mirrors `MAX_BATCH_RECIPIENTS` in
 * `contra.move`; Sui transaction-size and gas limits bind well below this in practice.
 */
const MAX_BATCH_RECIPIENTS = 255;

/** Build a `vector<u8>` memo argument; an absent or empty string encodes as an empty vector. */
function memoBytes(memo?: string): number[] {
	return memo ? Array.from(new TextEncoder().encode(memo)) : [];
}

/** Split a u64 value into four u16 limbs (little-endian). */
function intoLimbs(value: bigint): readonly [bigint, bigint, bigint, bigint] {
	return [
		value & 0xffffn,
		(value >> 16n) & 0xffffn,
		(value >> 32n) & 0xffffn,
		(value >> 48n) & 0xffffn,
	];
}

/**
 * BCS schema for the dynamic `Field<TokenAccountKey<T>, TokenAccount<T>>`
 * object that backs per-token account state. Cached at module scope so
 * each call site reuses the same schema instance.
 */
const TokenAccountField = DynamicField(
	contraContracts.TokenAccountKey,
	contraContracts.TokenAccount,
);
