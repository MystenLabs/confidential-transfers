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
	AccountDoesNotExistError,
	InsufficientBalanceError,
	InvalidArgumentError,
	ReceiverDoesNotAcceptDepositsError,
	TokenAccountDoesNotExistError,
} from './error.js';
import {
	buildAuditorPackageOption,
	buildDdhProof,
	buildElGamalProof,
	buildEncryptedAmount,
	buildEncryptedAmountAndProof,
	buildGVector,
	buildOptionalPublicKey,
	buildPublicKey,
	buildWellFormedProof,
	getAccountId,
	getConfidentialTokenId,
	getTokenAccountId,
	point,
	PROTOCOL_AUDITOR_ELGAMAL,
	PROTOCOL_BATCH_DDH,
	PROTOCOL_DDH,
	PROTOCOL_ELGAMAL,
	PROTOCOL_RANGE_PROOF_16,
	type WellFormedLimb,
} from './helpers.js';
import { DdhNizk, ElGamalNizk } from './nizk.js';
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
	RegisterWithDefaultPkOptions,
	RekeyTokenAccountOptions,
	SetDefaultPkAsSenderOptions,
	ShareAccountOptions,
	TokenAuditor,
	TokenBalance,
	TokenKeyStatus,
	TransferOptions,
	TryRekeyTokenAccountsOptions,
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
	 *
	 * With `autoRegisterFallback`, a receiver that has no `TokenAccount<T>` yet does not throw: its
	 * state is taken from the receiver's `Account` (`pk = Account.default_pk`, deposits accepted, not frozen)
	 * and flagged `needsRegistration`, so the caller can prepend a `register_with_default_pk` call
	 * before depositing (deposits no longer auto-register on chain). A receiver with no `Account` at
	 * all still throws.
	 */
	async #getAccountStates(
		addresses: readonly string[],
		tokenType: string,
		{ autoRegisterFallback = false }: { autoRegisterFallback?: boolean } = {},
	): Promise<AccountState[]> {
		const objectIds = addresses.map((a) => this.getTokenAccountId(a, tokenType));

		// TODO: consider exposing a function that receives the objects from the caller,
		// so that the caller could fetch them differently.
		const { objects } = await this.#suiClient.core.getObjects({
			objectIds,
			include: { content: true },
		});

		// For auto-registration, resolve any missing token accounts from the receiver's `Account`
		// (created on first receive) in a single follow-up multi-get.
		const missing = autoRegisterFallback
			? objects.flatMap((object, i) => (object instanceof Error ? [i] : []))
			: [];
		const accountFallback = new Map<number, AccountState>();
		if (missing.length > 0) {
			const { objects: accounts } = await this.#suiClient.core.getObjects({
				objectIds: missing.map((i) => this.getAccountId(addresses[i])),
				include: { content: true },
			});
			accounts.forEach((account, k) => {
				const i = missing[k];
				if (account instanceof Error) {
					throw new TokenAccountDoesNotExistError(addresses[i], account.message);
				}
				// `default_pk` is the account's optional default key. A missing token account can only be
				// auto-registered (and deposited to) when it is set — that key becomes the token's key.
				const accountPk = contraContracts.Account.parse(account.content).default_pk;
				if (!accountPk) {
					throw new TokenAccountDoesNotExistError(
						addresses[i],
						'account has no default key set, so no token account can be auto-registered for it',
					);
				}
				accountFallback.set(i, {
					pk: pointFromBcs(accountPk.element),
					acceptsEncryptedDeposits: true,
					isFrozen: false,
					needsRegistration: true,
				});
			});
		}

		return objects.map((object, i) => {
			if (object instanceof Error) {
				const fallback = accountFallback.get(i);
				if (fallback) return fallback;
				throw new TokenAccountDoesNotExistError(addresses[i], object.message);
			}
			const parsed = TokenAccountField.parse(object.content).value;
			return {
				pk: pointFromBcs(parsed.pk.element),
				acceptsEncryptedDeposits: parsed.accepts_deposits,
				isFrozen: parsed.is_frozen,
				needsRegistration: false,
			};
		});
	}

	/** The shared `AccountRegistry` object ID accounts are derived from. */
	get accountRegistryId(): string {
		return this.#packageConfig.accountRegistryId;
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
	 * Create a new account owned by `owner`, with no default key set. Permissionless — anyone can
	 * create the account for any owner; it only reserves the owner's derived slot and sets no key.
	 * Set a default key afterwards with `setDefaultPkAsSender` (needed only so others can
	 * auto-register tokens for the account via `register_with_default_pk`). Per-token keys are chosen
	 * independently at `register`.
	 *
	 * @example
	 * ```ts
	 * const tx = new Transaction();
	 * const account = tx.add(contraClient.newAccount({ owner: address }));
	 * tx.add(contraClient.shareAccount({ account }));
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAccountAlreadyRegistered` — `owner` already has an account (one per address).
	 */
	newAccount({ owner }: NewAccountOptions) {
		return contraContracts.newAccount({
			package: this.#packageConfig.packageId,
			arguments: {
				registry: this.#packageConfig.accountRegistryId,
				owner,
			},
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
	 * Report, for each token, the key that token's balances are currently encrypted under. Pass
	 * `tokenTypes` to query specific tokens, or omit it to enumerate every token registered on the
	 * account (its `TokenAccount` dynamic fields). Use it to see each token's current key — e.g. after
	 * `tryRekeyTokenAccounts`, compare each token's reported key against the key you intended and retry any
	 * that didn't take (a soft-failed re-key still reports the old key). A token's balance can only be
	 * re-keyed or decrypted with the key it currently reports (`publicKey`), so an old private key is
	 * safe to delete only once **no** token still reports it (omit `tokenTypes` to check them all).
	 *
	 * @example
	 * ```ts
	 * const tokens = await client.getTokenKeys(address); // every token
	 * const oldKeyStillUsed = tokens.some((t) => t.publicKey?.equals(oldPublicKey));
	 * ```
	 *
	 * Throws `AccountDoesNotExistError` if `address` has no `Account`.
	 */
	async getTokenKeys(address: string, tokenTypes?: readonly string[]): Promise<TokenKeyStatus[]> {
		const types = tokenTypes ?? (await this.#listTokenTypes(address));
		const objectIds = [
			this.getAccountId(address),
			...types.map((t) => this.getTokenAccountId(address, t)),
		];
		const {
			objects: [accountObject, ...tokenObjects],
		} = await this.#suiClient.core.getObjects({ objectIds, include: { content: true } });

		if (accountObject instanceof Error) {
			throw new AccountDoesNotExistError(address, accountObject.message);
		}

		return tokenObjects.map((object, i) => {
			if (object instanceof Error) {
				return { tokenType: types[i], registered: false };
			}
			const publicKey = pointFromBcs(TokenAccountField.parse(object.content).value.pk.element);
			return { tokenType: types[i], registered: true, publicKey };
		});
	}

	/**
	 * Enumerate the token types registered on `address`'s account by listing its dynamic fields (an
	 * `Account` stores only `TokenAccount<T>`s as dynamic fields, so the field `valueType`s carry every
	 * `T`). Returns `[]` when the account has no token accounts (or does not exist).
	 */
	async #listTokenTypes(address: string): Promise<string[]> {
		const parentId = this.getAccountId(address);
		const marker = '::contra::TokenAccount<';
		const types: string[] = [];
		let cursor: string | null = null;
		do {
			const page = await this.#suiClient.core.listDynamicFields({ parentId, cursor });
			for (const field of page.dynamicFields) {
				const start = field.valueType.indexOf(marker);
				if (start >= 0 && field.valueType.endsWith('>')) {
					types.push(field.valueType.slice(start + marker.length, -1));
				}
			}
			cursor = page.hasNextPage ? page.cursor : null;
		} while (cursor);
		return types;
	}

	/**
	 * Fetch the current per-transfer auditor configuration for the given token type.
	 *
	 * Returns the current auditor public key (`undefined` when auditing is disabled), the previous
	 * key retained across a rotation, and the epoch through which that previous key still audits
	 * in-flight transfers.
	 *
	 * @example
	 * ```ts
	 * const { currentPk, previousPk, previousExpirationEpoch } =
	 *   await contraClient.getAuditor('0x2::sui::SUI');
	 * ```
	 *
	 * Throws the underlying fetch error if any.
	 */
	async getAuditor(tokenType: string): Promise<TokenAuditor> {
		const { auditor } = await this.#getConfidentialToken(tokenType);
		return {
			currentPk: auditor.current_pk ? pointFromBcs(auditor.current_pk) : undefined,
			previousPk: auditor.previous_pk ? pointFromBcs(auditor.previous_pk) : undefined,
			previousExpirationEpoch: BigInt(auditor.previous_expiration_epoch),
		};
	}

	/**
	 * Fetch and parse the on-chain `ConfidentialToken<T>` object. Used to read
	 * `is_active` (global freeze) and the auditor key; the auditor exposure goes
	 * through `getAuditor`.
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
	 * Register a token account for `tokenAccount.tokenType` inside the
	 * account owned by `tokenAccount.address`.
	 *
	 * The token balance is keyed under `tokenAccount.publicKey`, chosen independently of the account's
	 * optional default key. Under per-transfer auditing registration carries no auditor data.
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
	 * const account = tx.add(
	 *   contraClient.newAccount({ owner: senderAddress, publicKey: tokenAccount.publicKey }),
	 * );
	 * tx.add(await contraClient.register({ tokenAccount, account }));
	 * tx.add(contraClient.shareAccount({ account }));
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAccountAlreadyRegistered` — the account is already registered for `T`.
	 * - `EAuthorizationError` — `auth` was invalid.
	 */
	async register({
		tokenAccount,
		account,
		auth,
	}: RegisterOptions): Promise<(tx: Transaction) => TransactionResult> {
		const { address, tokenType } = tokenAccount;
		const pid = this.#packageConfig.packageId;

		return (tx: Transaction): TransactionResult =>
			tx.add(
				contraContracts.register({
					package: pid,
					typeArguments: [tokenType],
					arguments: {
						account: account ?? this.getAccountId(address),
						auth: auth ? auth(tx) : this.#asSenderAuth(tx, tokenType),
						pk: buildPublicKey(pid, tokenAccount.publicKey),
					},
				}),
			);
	}

	/**
	 * Register a `TokenAccount<T>` for `receiver` on their behalf, without any `Auth` — the
	 * permissionless counterpart to `register`. Only succeeds when the token leaves registration
	 * permissionless, and `receiver` must already have an `Account`. `transferBatch` and `wrap` call
	 * this automatically for an unregistered receiver, so use it directly only to pre-register.
	 *
	 * @example
	 * ```ts
	 * const tx = new Transaction();
	 * tx.add(contraClient.registerWithDefaultPk({ receiver, tokenType }));
	 * ```
	 *
	 * On-chain aborts:
	 * - `ERegistrationNotPermissionless` — the token's registration is permissioned.
	 * - `EAccountAlreadyRegistered` — `receiver` is already registered for `T`.
	 * - `sui::dynamic_field::EFieldDoesNotExist` — `receiver` has no `Account`.
	 */
	registerWithDefaultPk({ receiver, tokenType }: RegisterWithDefaultPkOptions) {
		return (tx: Transaction): TransactionResult =>
			tx.add(
				contraContracts.registerWithDefaultPk({
					package: this.#packageConfig.packageId,
					typeArguments: [tokenType],
					arguments: {
						account: this.getAccountId(receiver),
						ct: this.#getConfidentialTokenId(tokenType),
					},
				}),
			);
	}

	/**
	 * Wrap a public coin into the receiver's pending encrypted balance.
	 *
	 * The supplied coin is consumed, its value is added to the pool for
	 * that token, and the same amount is credited to the receiver's
	 * pending public balance. The receiver must already have an `Account`
	 * shared on chain; if they have no `TokenAccount<T>` yet it is registered
	 * on their behalf in the same PTB (permissionless tokens only), since
	 * wrapping no longer auto-registers on chain.
	 *
	 * @example
	 * ```ts
	 * const tx = new Transaction();
	 * const [payment] = tx.splitCoins(tx.object(sourceCoinId), [10n]);
	 * tx.add(
	 *   await contraClient.wrap({
	 *     coin: payment,
	 *     receiver: receiverAddress,
	 *     tokenType: '0x2::sui::SUI',
	 *   }),
	 * );
	 * ```
	 *
	 * SDK-thrown:
	 * - `TokenAccountDoesNotExistError` — `receiver` has no `Account` at all.
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `ETransferDenied` — the token is paused, the deny list is globally frozen, the receiver
	 *   is on the deny list, or the receiver's per-account freeze is active.
	 * - `ERegistrationNotPermissionless` — `receiver` had no `TokenAccount<T>` and the token's
	 *   registration is permissioned, so the auto-inserted `register_with_default_pk` aborts.
	 */
	async wrap({
		coin,
		receiver,
		tokenType,
		memo,
	}: WrapOptions): Promise<(tx: Transaction) => TransactionResult> {
		// Wrapping no longer auto-registers on chain. If the receiver has an `Account` but no
		// `TokenAccount<T>` yet, register it on their behalf first (permissionless tokens only).
		const [{ needsRegistration }] = await this.#getAccountStates([receiver], tokenType, {
			autoRegisterFallback: true,
		});
		return (tx: Transaction): TransactionResult => {
			if (needsRegistration) {
				tx.add(this.registerWithDefaultPk({ receiver, tokenType }));
			}
			return tx.add(
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
		};
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
		balanceProof: DdhNizk;
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
		const ddhDst = tokenAccount.dst(PROTOCOL_DDH);
		const newBalance = intoLimbs(spendable - amount).map((v) => ({
			value: v,
			...Ciphertext.encryptWithBlinding(pk, v, randomScalar()),
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
	 * generated `contra::update_active_balance` Move call for `tokenAccount`. Used by `updateBalance`.
	 */
	#updateActiveBalance(
		batchRangeProver: BatchRangeProver,
		tx: Transaction,
		tokenAccount: TokenAccount,
		newBalance: WellFormedLimb[],
		balanceProof: DdhNizk,
		auth: TransactionObjectArgument,
	): TransactionResult {
		const pid = this.#packageConfig.packageId;
		const { encryptedAmount, wellFormedProof } = buildEncryptedAmountAndProof(
			batchRangeProver,
			tokenAccount.dst(PROTOCOL_RANGE_PROOF_16),
			tokenAccount.dst(PROTOCOL_ELGAMAL),
			tx,
			pid,
			{ limbs: newBalance, pk: tokenAccount.publicKey },
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
	 * before re-keying: a successful `tryRekeyTokenAccount` / `tryRekeyTokenAccounts` resumes deposits
	 * (unpauses) at the end, now under the new key; a token whose re-key soft-fails stays paused for a
	 * retry.
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
	 * Set the account's optional default key (`Account.default_pk`) to `defaultPk`, or clear it by
	 * passing `null`/omitting it (which disables permissionless auto-registration for this account).
	 * This is purely the key `register_with_default_pk` uses; per-token keys are unaffected and are
	 * rotated independently via `rekeyTokenAccount`. Restricted to the owner: the transaction must be signed
	 * by `account` (the account owner). For an object-owned account, call
	 * `contra::set_default_pk_as_object` directly.
	 *
	 * IMPORTANT: when you rotate a token's key, retain the OLD private key until that token has been
	 * re-keyed. A not-yet-re-keyed token's balance remains encrypted under the old key, and both
	 * re-keying it (the proof witness is `newSk * oldSk^-1`) and decrypting it require the old key.
	 * Discarding the old key while any token is still under it makes that balance permanently
	 * unrecoverable.
	 *
	 * @example
	 * ```ts
	 * const newTokenAccount = new TokenAccount(address, tokenType, packageConfig, randomScalar());
	 * tx.add(client.contra.setDefaultPkAsSender({ account: address, defaultPk: newTokenAccount.publicKey }));
	 * ```
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — the transaction sender is not `account`.
	 * - `EIdentityPublicKey` — `defaultPk` is the group identity.
	 */
	setDefaultPkAsSender({
		account,
		defaultPk,
	}: SetDefaultPkAsSenderOptions): (tx: Transaction) => TransactionResult {
		return (tx: Transaction) =>
			tx.add(
				contraContracts.setDefaultPkAsSender({
					package: this.#packageConfig.packageId,
					arguments: {
						account: this.getAccountId(account),
						defaultPk: buildOptionalPublicKey(
							this.#packageConfig.packageId,
							defaultPk ?? undefined,
						),
					},
				}),
			);
	}

	/**
	 * Fetch the token's active balance and build the re-key material mapping it from the old key to
	 * the new key: the four new decryption handles (`w * D_i`) and the batched DDH proof
	 * (`w = newSk * oldSk^{-1}` maps `[oldPk, D_0..3]` to `[newPk, D'_0..3]`). When the token has
	 * pending deposits and `merge` is set, the handles fold in the pending deposits' handles so the
	 * proof matches the post-merge active balance.
	 */
	async #buildRekeyMaterial(
		tokenAccount: TokenAccount,
		newTokenAccount: TokenAccount,
		merge: boolean,
	): Promise<{
		shouldMerge: boolean;
		newHandles: PublicKey[];
		rekeyProof: DdhNizk;
	}> {
		const oldPk = tokenAccount.publicKey;
		const newPk = newTokenAccount.publicKey;
		const { balance, pending, pendingPublicBalance } = await this.getBalance(tokenAccount);

		// `rekey_token_account` requires an empty pending balance; merge folds pending (encrypted + public)
		// into active first. Public deposits contribute a zero handle, so they don't affect the
		// handle mapping — only the encrypted pending handles do.
		const shouldMerge =
			merge && (pending.upperBound > 0 || pending.amount > 0n || pendingPublicBalance > 0n);

		const activeLimbs = [
			balance.ciphertext.l0,
			balance.ciphertext.l1,
			balance.ciphertext.l2,
			balance.ciphertext.l3,
		];
		const pendingLimbs = [
			pending.ciphertext.l0,
			pending.ciphertext.l1,
			pending.ciphertext.l2,
			pending.ciphertext.l3,
		];
		const oldHandles = activeLimbs.map((limb, i) =>
			shouldMerge
				? limb.decryptionHandle.add(pendingLimbs[i].decryptionHandle)
				: limb.decryptionHandle,
		);

		const w = ristretto255.Point.Fn.create(
			newTokenAccount.privateKey * ristretto255.Point.Fn.inv(tokenAccount.privateKey),
		);
		const newHandles = oldHandles.map((h) => mul(h, w));
		const rekeyProof = DdhNizk.prove(
			tokenAccount.dst(PROTOCOL_BATCH_DDH),
			w,
			[oldPk, ...oldHandles],
			[newPk, ...newHandles],
		);
		return { shouldMerge, newHandles, rekeyProof };
	}

	/**
	 * Emit the `rekey_token_account` (or `try_rekey_token_account`) Move call re-keying the token's active balance
	 * from its current `TokenAccount.pk` to `newPk` (explicit and independent of the account's default
	 * key). Shared by `rekeyTokenAccount`, `tryRekeyTokenAccount`, and `tryRekeyTokenAccounts`.
	 */
	#rekeyTokenAccountCall(
		tx: Transaction,
		tokenAccount: TokenAccount,
		newPk: PublicKey,
		newHandles: PublicKey[],
		rekeyProof: DdhNizk,
		auth: TransactionObjectArgument,
		soft: boolean,
	): TransactionResult {
		const pid = this.#packageConfig.packageId;
		const options = {
			package: pid,
			typeArguments: [tokenAccount.tokenType] as [string],
			arguments: {
				account: this.getAccountId(tokenAccount.address),
				auth,
				newPk: buildPublicKey(pid, newPk),
				newHandles: buildGVector(pid, newHandles),
				rekeyProof: buildDdhProof(pid, rekeyProof),
			},
		};
		return tx.add(
			soft
				? contraContracts.tryRekeyTokenAccount(options)
				: contraContracts.rekeyTokenAccount(options),
		);
	}

	/**
	 * Re-key one token's active balance to `newTokenAccount.publicKey`. The target key is explicit and
	 * independent of the account's default key (`Account.default_pk`), so no `setDefaultPkAsSender` is required first.
	 * When the token has pending deposits and `merge` is `true` (the default), a `merge` is prepended
	 * so the re-key (which requires an empty pending) can proceed.
	 *
	 * SDK-thrown:
	 * - `TokenAccountDoesNotExistError` — `tokenAccount` is not registered for the token.
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `EPendingDepositsMustBeMerged` — the token still has pending deposits (e.g. `merge=false`).
	 * - `EAmountsEqualityProofFailed` — the re-key proof did not verify (e.g. a deposit raced the
	 *   SDK's balance read). Use `tryRekeyTokenAccount` to soft-fail instead of aborting.
	 */
	async rekeyTokenAccount({
		tokenAccount,
		newTokenAccount,
		merge = true,
		auth,
	}: RekeyTokenAccountOptions): Promise<(tx: Transaction) => TransactionResult> {
		const { shouldMerge, newHandles, rekeyProof } = await this.#buildRekeyMaterial(
			tokenAccount,
			newTokenAccount,
			merge,
		);
		return (tx: Transaction) => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenAccount.tokenType);
			if (shouldMerge) tx.add(this.#merge({ tokenAccount, auth: authArg }));
			return this.#rekeyTokenAccountCall(
				tx,
				tokenAccount,
				newTokenAccount.publicKey,
				newHandles,
				rekeyProof,
				authArg,
				false,
			);
		};
	}

	/**
	 * Like `rekeyTokenAccount`, but soft-fails instead of aborting when the re-key proof does not verify
	 * (e.g. a deposit raced the balance read): the token is left stale for a retry and a
	 * `TryTokenRekeyFailedEvent` is emitted. Lets `setDefaultPkAsSender` and re-keys of several tokens ride
	 * in one PTB without pausing.
	 */
	async tryRekeyTokenAccount({
		tokenAccount,
		newTokenAccount,
		merge = true,
		auth,
	}: RekeyTokenAccountOptions): Promise<(tx: Transaction) => TransactionResult> {
		const { shouldMerge, newHandles, rekeyProof } = await this.#buildRekeyMaterial(
			tokenAccount,
			newTokenAccount,
			merge,
		);
		return (tx: Transaction) => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenAccount.tokenType);
			if (shouldMerge) tx.add(this.#merge({ tokenAccount, auth: authArg }));
			return this.#rekeyTokenAccountCall(
				tx,
				tokenAccount,
				newTokenAccount.publicKey,
				newHandles,
				rekeyProof,
				authArg,
				true,
			);
		};
	}

	/**
	 * Optimistically re-key one or more tokens in one PTB, without pausing — the batched, soft-failing
	 * plural of `tryRekeyTokenAccount`. For each `(current, new)` pair in `rotations`, an optional `merge` then
	 * `tryRekeyTokenAccount` from the current key to the paired new key. Because each re-key soft-fails (it does
	 * not abort), any token whose re-key races a concurrent deposit is left stale for a later retry while
	 * the rest still land — so it never reverts. Different tokens may re-key to different keys.
	 *
	 * This does not touch the account's default key (used by `register_with_default_pk`); set that
	 * separately with `setDefaultPkAsSender` if you want it changed. All accounts must be for the same account
	 * (same `address`).
	 *
	 * There is no SDK-side key check: if a pair's `tokenAccount` key doesn't match the token's real
	 * on-chain `TokenAccount.pk`, its re-key proof won't verify, so `try_rekey_token_account` soft-fails and it
	 * stays stale. After the tx, re-query `getTokenKeys` and compare each token's key against the key you
	 * intended — any that still reports its old key needs a retry.
	 *
	 * The returned thunk adds several calls, so apply it directly rather than via `tx.add`.
	 *
	 * @example
	 * ```ts
	 * const rekey = await client.contra.tryRekeyTokenAccounts({
	 *   rotations: [{ tokenAccount, newTokenAccount }],
	 * });
	 * const tx = new Transaction();
	 * rekey(tx);
	 * ```
	 */
	async tryRekeyTokenAccounts({
		rotations,
		merge = true,
	}: TryRekeyTokenAccountsOptions): Promise<(tx: Transaction) => void> {
		if (rotations.length === 0) {
			throw new InvalidArgumentError('tryRekeyTokenAccounts: `rotations` must not be empty.');
		}
		const { address } = rotations[0].tokenAccount;
		if (rotations.some((r) => r.tokenAccount.address !== address)) {
			throw new InvalidArgumentError(
				'tryRekeyTokenAccounts: all token accounts must be for the same account.',
			);
		}
		// Re-key material per pair: from the current `tokenAccount`'s key to the paired `newTokenAccount`.
		const materials = await Promise.all(
			rotations.map((r) => this.#buildRekeyMaterial(r.tokenAccount, r.newTokenAccount, merge)),
		);
		return (tx: Transaction) => {
			// Optimistically merge + re-key each token to its own new key.
			rotations.forEach((r, i) => {
				const { shouldMerge, newHandles, rekeyProof } = materials[i];
				const authArg = this.#asSenderAuth(tx, r.tokenAccount.tokenType);
				if (shouldMerge) tx.add(this.#merge({ tokenAccount: r.tokenAccount, auth: authArg }));
				this.#rekeyTokenAccountCall(
					tx,
					r.tokenAccount,
					r.newTokenAccount.publicKey,
					newHandles,
					rekeyProof,
					authArg,
					true,
				);
			});
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
	 * - `TokenAccountDoesNotExistError` — the sender is not registered for the token, or a receiver
	 *   has no `Account` at all. A receiver that has an `Account` but no `TokenAccount<T>` yet is
	 *   registered on their behalf in the same PTB (permissionless tokens only).
	 *
	 * On-chain aborts:
	 * - `EAuthorizationError` — invalid `auth`.
	 * - `ETransferDenied` — the token is paused, the deny list is globally frozen, the sender
	 *   or a receiver is on the deny list, the sender has a per-account freeze active (the
	 *   receiver-frozen case is caught by the SDK), or a receiver's state changed between the
	 *   SDK check and execution.
	 * - `ERegistrationNotPermissionless` — a receiver had no `TokenAccount<T>` and the token's
	 *   registration is permissioned, so the auto-inserted `register_with_default_pk` aborts.
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
			{ autoRegisterFallback: true },
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
				...Ciphertext.encryptWithBlinding(receiverPk, value, randomness.blinding(i, j)),
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
		const consistencyProof = ElGamalNizk.prove(elgamalDst, senderPk, [
			{ ciphertext: totalSenderEnc, value: totalAmount, blinding: totalBlinding },
		]);

		const { shouldMerge, newBalance, balanceProof } = await this.#createBalanceUpdate(
			tokenAccount,
			totalAmount,
			merge,
			totalSenderEnc,
		);

		const { batchRangeProver } = await this.#getBulletproofs();

		// Per-transfer auditing: when the token has an auditor key, attach two u32-limb decryption
		// handles per receiver plus one batched `ElGamalProof` over the derived `(commitment, handle)`
		// pairs. Both are `none` when auditing is disabled.
		const auditor = await this.getAuditor(tokenType);
		const auditorData = auditor.currentPk
			? buildAuditorData(tokenAccount.dst(PROTOCOL_AUDITOR_ELGAMAL), auditor.currentPk, prepared)
			: undefined;

		return (tx: Transaction): TransactionResult => {
			const authArg = auth ? auth(tx) : this.#asSenderAuth(tx, tokenType);
			if (shouldMerge) {
				tx.add(this.#merge({ tokenAccount, auth: authArg }));
			}

			// Deposits no longer auto-register on chain: any receiver that has an `Account` but no
			// `TokenAccount<T>` yet is registered on their behalf first via `register_with_default_pk`
			// (permissionless tokens only; the call aborts otherwise).
			recipients.forEach((recipient, i) => {
				if (receiverStates[i].needsRegistration) {
					tx.add(this.registerWithDefaultPk({ receiver: recipient.receiverAddress, tokenType }));
				}
			});

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
							elgamalDst,
							pid,
							[
								...prepared.map((p) => ({ limbs: p.encAmountReceiver, pk: p.receiverPk })),
								{ limbs: newBalance, pk: senderPk },
							],
						),
						totalSenderHandle: point(totalSenderEnc.decryptionHandle.toBytes()),
						consistencyProof: buildElGamalProof(pid, consistencyProof),
						seedPoint: point(randomness.seedPoint.toBytes()),
						newBalance: buildEncryptedAmount(
							pid,
							newBalance.map((l) => l.ciphertext),
						),
						balanceProof: buildDdhProof(pid, balanceProof),
						auditorPackage: buildAuditorPackageOption(pid, auditorData),
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
					tokenAccount.dst(PROTOCOL_ELGAMAL),
					tx,
					pid,
					{ limbs: newBalance, pk: tokenAccount.publicKey },
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
	/**
	 * True when the address has an `Account` but no `TokenAccount<T>` yet, so this state was resolved
	 * from the `Account` fallback (see `#getAccountStates` with `autoRegisterFallback`). The caller
	 * must prepend a `register_with_default_pk` call before depositing to it.
	 */
	needsRegistration: boolean;
}

/** Max recipients in a single `transferBatch` PTB. Mirrors `MAX_BATCH_RECIPIENTS` in `contra.move`. */
const MAX_BATCH_RECIPIENTS = 255;

/** A prepared receiver amount: its four well-formed limbs (value/blinding/ciphertext) and its pk. */
type PreparedAmount = { receiverPk: PublicKey; encAmountReceiver: WellFormedLimb[] };

/**
 * Build the per-transfer auditor data (Appendix C): for each receiver, regroup its four u16 limbs
 * into two u32-limb `(commitment, handle)` pairs under `auditorPk` — commitment
 * `Č_k = C_{2k} + 2^16 C_{2k+1}` (reusing the receiver's range-proven commitments), handle
 * `D̃_k = ρ̃_k · auditorPk` with `ρ̃_k = ρ_{2k} + 2^16 ρ_{2k+1}`. Returns the flattened handles (two
 * per receiver, in `prepared` order — matching `add_to_batch`'s consumption order) and one batched
 * `ElGamalNizk` over every derived pair, all under the single `auditorPk`.
 */
function buildAuditorData(
	dst: Uint8Array,
	auditorPk: PublicKey,
	prepared: readonly PreparedAmount[],
): { handles: PublicKey[]; proof: ElGamalNizk } {
	const shift = 1n << 16n;
	const handles: PublicKey[] = [];
	const entries: { ciphertext: Ciphertext; value: bigint; blinding: bigint }[] = [];
	for (const p of prepared) {
		const limbs = p.encAmountReceiver;
		for (const [lo, hi] of [
			[0, 1],
			[2, 3],
		] as const) {
			const blinding = ristretto255.Point.Fn.create(
				limbs[lo].blinding + shift * limbs[hi].blinding,
			);
			const value = limbs[lo].value + shift * limbs[hi].value;
			const commitment = limbs[lo].ciphertext.ciphertext.add(
				mul(limbs[hi].ciphertext.ciphertext, shift),
			);
			const handle = mul(auditorPk, blinding);
			handles.push(handle);
			entries.push({ ciphertext: new Ciphertext(commitment, handle), value, blinding });
		}
	}
	return { handles, proof: ElGamalNizk.prove(dst, auditorPk, entries) };
}

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
