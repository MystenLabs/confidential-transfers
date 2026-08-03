/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * Confidential transfers on Sui.
 *
 * Enables token transfers where amounts are encrypted using twisted ElGamal
 * encryption while remaining verifiable through zero-knowledge proofs.
 *
 * ## Key Flows for the Token Issuer of public token type `T`:
 *
 * 1.  Create a new confidential token for a token type `T` (using the
 *     TreasuryCap), optionally with an initial set of auditor public keys.
 *     Creation returns a `ManagementCap<T>`.
 * 2.  Set the freeze admins who can freeze the token globally or specific accounts
 *     (via the ManagementCap). Those admins may monitor the confidential token and
 *     freeze it or individual accounts if necessary.
 * 3.  Unfreeze the token globally or a specific account (using the TreasuryCap).
 * 4.  Set the balance of an account directly, to emulate burn/seize (using the
 *     TreasuryCap).
 * 5.  Freeze specific accounts via the token's deny list, using
 *     `sui::coin::deny_list_v2_add` / `sui::coin::deny_list_v2_remove`. The deny
 *     list affects both the public and the private coin; to freeze only the
 *     private coin, see items 2 and 3.
 * 6.  Rotate or disable the auditor key set via `update_auditors` (using the
 *     ManagementCap). Setting `bump_recommended_min` raises the auditors'
 *     `recommended_min_version` to the new version, signalling to wallets that
 *     every user should refresh their key. Passing an empty `public_keys` vector
 *     disables the auditor flow.
 * 7.  [Advanced] Set the policy for the confidential token (using the
 *     TreasuryCap). Policies define which operations are permissioned. Currently
 *     supported permissioned operations are:
 *     - `register`: Register a token account for a token type `T`. E.g., caller
 *       ensures the user is KYCed before registering an account. When set, also
 *       setting the public key for an account is permissioned.
 *     - `wrap`: Wrap a public coin into a private balance. E.g., caller ensures
 *       the funds passed screening before wrapping.
 *     - `unwrap`: Unwrap a private balance into a public coin. E.g., caller
 *       enforces rate limit on exiting the system. Additional permissioned
 *       operations may be added in the future. Permissioned operations are
 *       customized flows that should be implemented by the issuer's contract, and
 *       may not be supported by all clients/wallets. The default policy is fully
 *       permissionless.
 *
 * ## Key Flows for Users:
 *
 * 1.  Create an account for an address (needed once for all token types).
 * 2.  Register a token account for a token type `T` with a public key `pk`. If the
 *     token has auditors configured, the user must additionally provide the user's
 *     key encrypted to every auditor public key in the current set, and a proof
 *     that the ciphertext encrypts its secret key.
 * 3.  Update the public key for a token account.
 * 4.  Wrap a public coin into a confidential token, adding to the pending
 *     encrypted balance of an account.
 * 5.  Transfer an encrypted amount to two or more token accounts.
 * 6.  Unwrap an encrypted amount from a token account and convert it to public
 *     coins.
 *
 * ## Authentication:
 *
 * Some functions require authorization via an `&Auth<T>` argument. Under the
 * default permissionless policy any `Auth<T>` is accepted; permissioning narrows
 * which constructors produce a valid `Auth<T>`. The caller constructs the
 * `Auth<T>` via one of three constructors:
 *
 * - `authorize_as_sender`: authenticates `ctx.sender()`. The standard path for
 *   end-user wallets and permissionless operations.
 * - `authorize_as_object`: authenticates the address derived from a given object's
 *   `UID`. Use this when access is controlled by a Move object (the holder of
 *   `&mut UID` proves ownership).
 * - `authorize_with_witness`: authenticates `owner` under a witness `W` required
 *   by the policy. Use this to implement custom permissioned operations: the
 *   issuer's contract holds `W`, performs its own checks (e.g. KYC, screening,
 *   rate limiting), and creates an `Auth<T>` for the requested operation.
 */

import { bcs, type BcsType } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import {
	MoveEnum,
	MoveStruct,
	MoveTuple,
	normalizeMoveArguments,
	type RawTransactionArgument,
} from '../utils/index.js';
import * as auditors from './auditors.js';
import * as balance from './balance.js';
import * as group_ops from './deps/sui/group_ops.js';
import * as vec_set from './deps/sui/vec_set.js';
import * as policy from './policy.js';

const $moduleName = '@local-pkg/contra::contra';
export const TokenRegistry = new MoveStruct({
	name: `${$moduleName}::TokenRegistry`,
	fields: {
		id: bcs.Address,
	},
});
export const AccountRegistry = new MoveStruct({
	name: `${$moduleName}::AccountRegistry`,
	fields: {
		id: bcs.Address,
	},
});
export const ConfidentialToken = new MoveStruct({
	name: `${$moduleName}::ConfidentialToken<phantom T>`,
	fields: {
		id: bcs.Address,
		is_active: bcs.bool(),
		freeze_admins: vec_set.VecSet(bcs.Address),
		policy: bcs.option(policy.Policy),
		auditor: auditors.Auditors,
	},
});
export const Pool = new MoveStruct({
	name: `${$moduleName}::Pool<phantom T>`,
	fields: {
		id: bcs.Address,
	},
});
export const Account = new MoveStruct({
	name: `${$moduleName}::Account`,
	fields: {
		id: bcs.Address,
		owner: bcs.Address,
		pk: group_ops.Element,
		key_rotation_epoch: bcs.u64(),
	},
});
export const TokenAccount = new MoveStruct({
	name: `${$moduleName}::TokenAccount<phantom T>`,
	fields: {
		pk: group_ops.Element,
		session_id: bcs.vector(bcs.u8()),
		is_frozen: bcs.bool(),
		accepts_deposits: bcs.bool(),
		active: balance.EncryptedBalance,
		pending: balance.EncryptedBalance,
		public_balance: balance.PublicCoin,
	},
});
export const TokenKey = new MoveTuple({
	name: `${$moduleName}::TokenKey<phantom T>`,
	fields: [bcs.bool()],
});
export const PoolKey = new MoveTuple({ name: `${$moduleName}::PoolKey`, fields: [bcs.bool()] });
export const TokenAccountKey = new MoveTuple({
	name: `${$moduleName}::TokenAccountKey<phantom T>`,
	fields: [bcs.bool()],
});
export const AccountKey = new MoveTuple({
	name: `${$moduleName}::AccountKey`,
	fields: [bcs.Address],
});
export const ManagementCap = new MoveStruct({
	name: `${$moduleName}::ManagementCap<phantom T>`,
	fields: {
		id: bcs.Address,
	},
});
/**
 * State machine for batched transfers from a single sender to multiple receivers.
 * Created by `batched_transfer`, consumed by calling `add` for each receiver then
 * `finalize`.
 */
export const TransferBatch = new MoveEnum({
	name: `${$moduleName}::TransferBatch<phantom T>`,
	fields: {
		/**
		 * The sender's balance proof failed. Subsequent `add` calls are no-ops;
		 * `try_finalize` returns `false` and `finalize` aborts.
		 */
		BalanceProofFailed: null,
		/**
		 * The balance proof succeeded. Holds the receiver-keyed `EncryptedCoin`s split off
		 * the sender's balance, one per transfer. `add_to_batch` pops one per receiver and
		 * credits it to their pending deposits. `seed_point` (= `P`) and `next_index` are
		 * carried only for the events: each `add_to_batch` emits `P` and the receiver's
		 * batch index so the sender can later re-derive that transfer's blinding
		 * (`seed = HKDF(sk * P)`) and recover the amount from the on-chain commitment,
		 * without any sender-keyed decryption handle. `sender_pk` is likewise carried only
		 * for the event.
		 */
		Ok: new MoveStruct({
			name: `TransferBatch.Ok`,
			fields: {
				sender: bcs.Address,
				sender_pk: group_ops.Element,
				coins: bcs.vector(balance.EncryptedCoin),
				seed_point: group_ops.Element,
				next_index: bcs.u8(),
				auditor_handles: bcs.vector(group_ops.Element),
			},
		}),
	},
});
export interface AuthorizeAsSenderArguments {
	ct: RawTransactionArgument<string>;
}
export interface AuthorizeAsSenderOptions {
	package?: string;
	arguments: AuthorizeAsSenderArguments | [ct: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Create an `Auth<T>` for `ctx.sender()` covering every operation the policy on
 * `ct` leaves permissionless.
 */
export function authorizeAsSender(options: AuthorizeAsSenderOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['ct'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'authorize_as_sender',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface AuthorizeWithWitnessArguments<W extends BcsType<any>> {
	ct: RawTransactionArgument<string>;
	operation: RawTransactionArgument<number>;
	owner: RawTransactionArgument<string>;
	witness: RawTransactionArgument<W>;
}
export interface AuthorizeWithWitnessOptions<W extends BcsType<any>> {
	package?: string;
	arguments:
		| AuthorizeWithWitnessArguments<W>
		| [
				ct: RawTransactionArgument<string>,
				operation: RawTransactionArgument<number>,
				owner: RawTransactionArgument<string>,
				witness: RawTransactionArgument<W>,
		  ];
	typeArguments: [string, string];
}
/**
 * Create an `Auth<T>` on behalf of `owner` covering the requested `operation`,
 * authorized by witness `W`. Aborts unless the policy on `ct` is set, its witness
 * type is `W`, and `operation` is permissioned. The witness-holding contract is
 * fully responsible for authenticating `owner`.
 */
export function authorizeWithWitness<W extends BcsType<any>>(
	options: AuthorizeWithWitnessOptions<W>,
) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, 'u8', 'address', `${options.typeArguments[1]}`] satisfies (
		| string
		| null
	)[];
	const parameterNames = ['ct', 'operation', 'owner', 'witness'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'authorize_with_witness',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface AuthorizeAsObjectArguments {
	ct: RawTransactionArgument<string>;
	uid: RawTransactionArgument<string>;
}
export interface AuthorizeAsObjectOptions {
	package?: string;
	arguments:
		| AuthorizeAsObjectArguments
		| [ct: RawTransactionArgument<string>, uid: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Create an `Auth<T>` on behalf of an object identified by `uid`, covering every
 * operation the policy on `ct` leaves permissionless. Holding `&mut UID` proves
 * custody of the object, so the object self-authenticates as its own `owner` (the
 * address derived from the UID).
 */
export function authorizeAsObject(options: AuthorizeAsObjectOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, '0x2::object::ID'] satisfies (string | null)[];
	const parameterNames = ['ct', 'uid'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'authorize_as_object',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface NewConfidentialTokenArguments {
	registry: RawTransactionArgument<string>;
	T: RawTransactionArgument<string>;
	auditorPk: TransactionArgument;
}
export interface NewConfidentialTokenOptions {
	package?: string;
	arguments:
		| NewConfidentialTokenArguments
		| [
				registry: RawTransactionArgument<string>,
				T: RawTransactionArgument<string>,
				auditorPk: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Create a new confidential token for the given token type. Can only happen once
 * per token type, and the token object is immediately shared.
 *
 * Requires a `&mut TreasuryCap` for authorization, this is to prevent frozen
 * TreasuryCaps from being used.
 *
 * Creates an `Auditors` object for the confidential token using the provided
 * auditor public key. The auditor key can be `none` initially and updated later by
 * the issuer.
 *
 * Returns the created `ConfidentialToken` and a `ManagementCap` that can be used
 * to perform administrative operations for this token.
 */
export function newConfidentialToken(options: NewConfidentialTokenOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null] satisfies (string | null)[];
	const parameterNames = ['registry', 'T', 'auditorPk'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'new_confidential_token',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface ShareConfidentialTokenArguments {
	ct: RawTransactionArgument<string>;
}
export interface ShareConfidentialTokenOptions {
	package?: string;
	arguments: ShareConfidentialTokenArguments | [ct: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Share the confidential token object. This is needed to allow the issuer to
 * interact with the confidential token, e.g., to set permissions, in the same PTB.
 */
export function shareConfidentialToken(options: ShareConfidentialTokenOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['ct'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'share_confidential_token',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface NewAccountArguments {
	registry: RawTransactionArgument<string>;
	owner: RawTransactionArgument<string>;
	pk: TransactionArgument;
}
export interface NewAccountOptions {
	package?: string;
	arguments:
		| NewAccountArguments
		| [
				registry: RawTransactionArgument<string>,
				owner: RawTransactionArgument<string>,
				pk: TransactionArgument,
		  ];
}
/**
 * Create a new account for the given address. Can only happen once per address.
 *
 * Note: the `owner` argument is not tied to `ctx.sender()` — anyone can create an
 * `Account` on behalf of any address. Since `Account` has `key` only (no `store`),
 * the only way to dispose of it outside this module is via `share_account`, and
 * all authenticated operations still gate on `account.owner == ctx.sender()`.
 */
export function newAccount(options: NewAccountOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, 'address', null] satisfies (string | null)[];
	const parameterNames = ['registry', 'owner', 'pk'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'new_account',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface ShareAccountArguments {
	account: RawTransactionArgument<string>;
}
export interface ShareAccountOptions {
	package?: string;
	arguments: ShareAccountArguments | [account: RawTransactionArgument<string>];
}
/**
 * Share the account object. This has do be done after `new_account`, but it allows
 * the user to create token accounts for confidential tokens immediately.
 */
export function shareAccount(options: ShareAccountOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['account'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'share_account',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface RegisterArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
}
export interface RegisterOptions {
	package?: string;
	arguments:
		| RegisterArguments
		| [account: RawTransactionArgument<string>, auth: TransactionArgument];
	typeArguments: [string];
}
/**
 * Create a `TokenAccount` for token `T`, with its balances keyed under the current
 * `account.pk`. Authorized by `auth`, which must be for the `PERMISSIONED_REGISTER`
 * operation and for `account.owner`. Under per-transfer auditing, registration
 * carries no auditor data.
 */
export function register(options: RegisterOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'register',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface SetAcceptsEncryptedDepositsArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	acceptsEncryptedDeposits: RawTransactionArgument<boolean>;
}
export interface SetAcceptsEncryptedDepositsOptions {
	package?: string;
	arguments:
		| SetAcceptsEncryptedDepositsArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				acceptsEncryptedDeposits: RawTransactionArgument<boolean>,
		  ];
	typeArguments: [string];
}
/**
 * Set whether this account for token `T` accepts new encrypted deposits. This is
 * used to prevent receiving new encrypted deposits during token account key
 * rotation. Authorized by `auth`, which must be for `account.owner`. Any `Auth<T>`
 * is accepted regardless of which operation it covers.
 */
export function setAcceptsEncryptedDeposits(options: SetAcceptsEncryptedDepositsOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'bool'] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'acceptsEncryptedDeposits'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'set_accepts_encrypted_deposits',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface SetAccountKeyArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	newPk: TransactionArgument;
}
export interface SetAccountKeyOptions {
	package?: string;
	arguments:
		| SetAccountKeyArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				newPk: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Rotate the account's key to `new_pk`. O(1): sets the convergence target
 * `account.pk`; it does not touch any token balance. Each token's balance stays
 * under its own `TokenAccount.pk` until the owner catches it up with `rekey_token`.
 * Authorized by `auth`, which must be for the `PERMISSIONED_REGISTER` operation and
 * may be for any token the account is registered for.
 */
export function setAccountKey(options: SetAccountKeyOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'newPk'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'set_account_key',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface RekeyTokenArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	newHandles: TransactionArgument;
	rekeyProof: TransactionArgument;
}
export interface RekeyTokenOptions {
	package?: string;
	arguments:
		| RekeyTokenArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				newHandles: TransactionArgument,
				rekeyProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Re-key token `T`'s active balance from its current `TokenAccount.pk` to the
 * account key `account.pk`, swapping each limb's decryption handle for the matching
 * `new_handles[i]` (proven by `rekey_proof`). Aborts if the token has unmerged
 * pending deposits (merge them first) or the proof fails. Authorized by `auth`,
 * which must be for the `PERMISSIONED_REGISTER` operation and for `account.owner`.
 */
export function rekeyToken(options: RekeyTokenOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'vector<null>', null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'newHandles', 'rekeyProof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'rekey_token',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface TryRekeyTokenArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	newHandles: TransactionArgument;
	rekeyProof: TransactionArgument;
}
export interface TryRekeyTokenOptions {
	package?: string;
	arguments:
		| TryRekeyTokenArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				newHandles: TransactionArgument,
				rekeyProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Like `rekey_token` but soft-fails instead of aborting: if the re-key proof does
 * not verify (e.g. a deposit raced the caller's read), it emits
 * `TryTokenRekeyFailedEvent` and returns `false`, leaving the token unchanged (still
 * stale) for a retry. Lets a caller bundle `set_account_key` and re-keys of several
 * tokens into one PTB without pausing. Still aborts on unmerged pending deposits.
 */
export function tryRekeyToken(options: TryRekeyTokenOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'vector<null>', null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'newHandles', 'rekeyProof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'try_rekey_token',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface WrapArguments {
	receiver: RawTransactionArgument<string>;
	auth: TransactionArgument;
	ct: RawTransactionArgument<string>;
	pool: RawTransactionArgument<string>;
	coin: RawTransactionArgument<string>;
	memo: RawTransactionArgument<Array<number>>;
}
export interface WrapOptions {
	package?: string;
	arguments:
		| WrapArguments
		| [
				receiver: RawTransactionArgument<string>,
				auth: TransactionArgument,
				ct: RawTransactionArgument<string>,
				pool: RawTransactionArgument<string>,
				coin: RawTransactionArgument<string>,
				memo: RawTransactionArgument<Array<number>>,
		  ];
	typeArguments: [string];
}
/**
 * Convert public coin to private tokens and add them to the public pending balance
 * of `receiver`. Authorized by `auth`, which must be for the `PERMISSIONED_WRAP`
 * operation; `auth` may be for any owner.
 */
export function wrap(options: WrapOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [
		null,
		null,
		null,
		'0x2::deny_list::DenyList',
		null,
		null,
		'vector<u8>',
	] satisfies (string | null)[];
	const parameterNames = ['receiver', 'auth', 'ct', 'pool', 'coin', 'memo'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'wrap',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface BatchedTransferArguments {
	sender: RawTransactionArgument<string>;
	auth: TransactionArgument;
	ct: RawTransactionArgument<string>;
	receiverPks: TransactionArgument;
	receiverAmounts: TransactionArgument;
	wellFormedProofs: TransactionArgument;
	totalSenderHandle: TransactionArgument;
	consistencyProof: TransactionArgument;
	seedPoint: TransactionArgument;
	newBalance: TransactionArgument;
	balanceProof: TransactionArgument;
	auditorHandles: TransactionArgument;
	auditorProof: TransactionArgument;
}
export interface BatchedTransferOptions {
	package?: string;
	arguments:
		| BatchedTransferArguments
		| [
				sender: RawTransactionArgument<string>,
				auth: TransactionArgument,
				ct: RawTransactionArgument<string>,
				receiverPks: TransactionArgument,
				receiverAmounts: TransactionArgument,
				wellFormedProofs: TransactionArgument,
				totalSenderHandle: TransactionArgument,
				consistencyProof: TransactionArgument,
				seedPoint: TransactionArgument,
				newBalance: TransactionArgument,
				balanceProof: TransactionArgument,
				auditorHandles: TransactionArgument,
				auditorProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Start a batched transfer from `sender`. `receiver_amounts[i]` is the transferred
 * value re-encrypted under `receiver_pks[i]`. `well_formed_proofs` is a single
 * batched `WellFormedProof` covering `receiver_amounts ++ [new_balance]` under
 * `receiver_pks ++ [sender_pk]` — one aggregate Bulletproof for the whole
 * transfer. `total_sender_handle` is the single sender-keyed decryption handle for
 * the transfer total; `consistency_proof` proves it well-formed and
 * `balance_proof` proves the sender's balance drops by exactly that total (see
 * `balance::try_split_batch`). `seed_point` (= `P`) is forwarded to the events so
 * the sender can re-derive each transfer's blinding and recover its outgoing
 * amounts; it is not otherwise verified on chain.
 *
 * Returns `TransferBatch::Ok` when `balance_proof` verifies, else
 * `BalanceProofFailed`. Aborts if `well_formed_proofs` does not verify or
 * `consistency_proof` fails. Call `add` once per receiver, in `receiver_amounts`
 * order, then `finalize`. Authorized by any `Auth<T>` for `sender.owner`.
 */
export function batchedTransfer(options: BatchedTransferOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [
		null,
		null,
		null,
		'0x2::deny_list::DenyList',
		'vector<null>',
		'vector<null>',
		null,
		null,
		null,
		null,
		null,
		null,
		null,
		null,
	] satisfies (string | null)[];
	const parameterNames = [
		'sender',
		'auth',
		'ct',
		'receiverPks',
		'receiverAmounts',
		'wellFormedProofs',
		'totalSenderHandle',
		'consistencyProof',
		'seedPoint',
		'newBalance',
		'balanceProof',
		'auditorHandles',
		'auditorProof',
	];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'batched_transfer',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface AddToBatchArguments {
	batch: TransactionArgument;
	receiver: RawTransactionArgument<string>;
	memo: RawTransactionArgument<Array<number>>;
}
export interface AddToBatchOptions {
	package?: string;
	arguments:
		| AddToBatchArguments
		| [
				batch: TransactionArgument,
				receiver: RawTransactionArgument<string>,
				memo: RawTransactionArgument<Array<number>>,
		  ];
	typeArguments: [string];
}
/**
 * Add a receiver to a batched transfer: pop the next receiver-keyed
 * `EncryptedCoin` and credit it to the receiver's pending deposits. Aborts if:
 *
 * - the receiver is not registered, frozen, or on the deny list,
 * - `add_to_batch` is called more times than there were `receiver_amounts` in
 *   `batched_transfer`,
 * - the coin is not encrypted under the receiver's registered public key.
 */
export function addToBatch(options: AddToBatchOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'vector<u8>', '0x2::deny_list::DenyList'] satisfies (
		| string
		| null
	)[];
	const parameterNames = ['batch', 'receiver', 'memo'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'add_to_batch',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface TryFinalizeArguments {
	batch: TransactionArgument;
}
export interface TryFinalizeOptions {
	package?: string;
	arguments: TryFinalizeArguments | [batch: TransactionArgument];
	typeArguments: [string];
}
/**
 * Consume the `TransferBatch` to complete the transfer batch and return `true` if
 * the transfer succeeded and `false` if the balance proof failed.
 */
export function tryFinalize(options: TryFinalizeOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['batch'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'try_finalize',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface FinalizeArguments {
	batch: TransactionArgument;
}
export interface FinalizeOptions {
	package?: string;
	arguments: FinalizeArguments | [batch: TransactionArgument];
	typeArguments: [string];
}
/**
 * Consume the `TransferBatch` to complete the transfer batch. Aborts if any check,
 * including the balance proof, failed.
 */
export function finalize(options: FinalizeOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['batch'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'finalize',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface MergeArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
}
export interface MergeOptions {
	package?: string;
	arguments: MergeArguments | [account: RawTransactionArgument<string>, auth: TransactionArgument];
	typeArguments: [string];
}
/**
 * Merge all pending deposits into the active balance. This must be done before
 * pending encrypted and public deposits can be used in a transfer. To prevent
 * overflows, the number of additions done with the active balance is limited,
 * including the number of additions done with the pending deposits. Authorized by
 * `auth`, which must be for `account.owner`. Any `Auth<T>` is accepted regardless
 * of which operation it covers.
 */
export function merge(options: MergeOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'merge',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface UpdateActiveBalanceArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	newBalance: TransactionArgument;
	newBalanceProof: TransactionArgument;
	balanceProof: TransactionArgument;
}
export interface UpdateActiveBalanceOptions {
	package?: string;
	arguments:
		| UpdateActiveBalanceArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				newBalance: TransactionArgument,
				newBalanceProof: TransactionArgument,
				balanceProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * This may be used to update the balance after merging many pending deposits
 * before merging new deposits. Authorized by `auth`, which must be for
 * `account.owner`. Any `Auth<T>` is accepted regardless of which operation it
 * covers.
 */
export function updateActiveBalance(options: UpdateActiveBalanceOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null, null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'newBalance', 'newBalanceProof', 'balanceProof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'update_active_balance',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface UnwrapArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	ct: RawTransactionArgument<string>;
	pool: RawTransactionArgument<string>;
	newBalance: TransactionArgument;
	newBalanceProof: TransactionArgument;
	amount: RawTransactionArgument<number | bigint>;
	balanceProof: TransactionArgument;
}
export interface UnwrapOptions {
	package?: string;
	arguments:
		| UnwrapArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				ct: RawTransactionArgument<string>,
				pool: RawTransactionArgument<string>,
				newBalance: TransactionArgument,
				newBalanceProof: TransactionArgument,
				amount: RawTransactionArgument<number | bigint>,
				balanceProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Take an amount of `Coin<T>` from the encrypted balance of `account`. Authorized
 * by `auth`, which must be for the `PERMISSIONED_UNWRAP` operation and for
 * `account.owner`. The caller needs to provide a proof that the new balance is
 * correct after taking the amount:
 *
 * - `new_balance` is the new encrypted balance of the account after taking the
 *   amount,
 * - `amount` is the amount of coins taken from the balance,
 * - `balance_proof` is a proof that `account.balance = new_balance + amount`.
 */
export function unwrap(options: UnwrapOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [
		null,
		null,
		null,
		'0x2::deny_list::DenyList',
		null,
		null,
		null,
		'u64',
		null,
	] satisfies (string | null)[];
	const parameterNames = [
		'account',
		'auth',
		'ct',
		'pool',
		'newBalance',
		'newBalanceProof',
		'amount',
		'balanceProof',
	];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'unwrap',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface TryUnwrapArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	ct: RawTransactionArgument<string>;
	pool: RawTransactionArgument<string>;
	newBalance: TransactionArgument;
	newBalanceProof: TransactionArgument;
	amount: RawTransactionArgument<number | bigint>;
	balanceProof: TransactionArgument;
}
export interface TryUnwrapOptions {
	package?: string;
	arguments:
		| TryUnwrapArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				ct: RawTransactionArgument<string>,
				pool: RawTransactionArgument<string>,
				newBalance: TransactionArgument,
				newBalanceProof: TransactionArgument,
				amount: RawTransactionArgument<number | bigint>,
				balanceProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Same as `unwrap` but does not abort if the balance proof fails. Instead, it
 * emits a `TryUnwrapFailedEvent` and returns a zero-value coin.
 */
export function tryUnwrap(options: TryUnwrapOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [
		null,
		null,
		null,
		'0x2::deny_list::DenyList',
		null,
		null,
		null,
		'u64',
		null,
	] satisfies (string | null)[];
	const parameterNames = [
		'account',
		'auth',
		'ct',
		'pool',
		'newBalance',
		'newBalanceProof',
		'amount',
		'balanceProof',
	];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'try_unwrap',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface OwnerArguments {
	account: RawTransactionArgument<string>;
}
export interface OwnerOptions {
	package?: string;
	arguments: OwnerArguments | [account: RawTransactionArgument<string>];
}
export function owner(options: OwnerOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['account'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'owner',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface SetBalanceByIssuerArguments {
	t: RawTransactionArgument<string>;
	account: RawTransactionArgument<string>;
	newBalance: TransactionArgument;
}
export interface SetBalanceByIssuerOptions {
	package?: string;
	arguments:
		| SetBalanceByIssuerArguments
		| [
				t: RawTransactionArgument<string>,
				account: RawTransactionArgument<string>,
				newBalance: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * A function for the issuer to set the balance of an account directly. This is
 * used in cases where the issuer needs to intervene.
 *
 * WARNING: This may break the consistency of the balance such that the number of
 * confidential tokens in circulation does not match the amount of coins in the
 * pool. It is the responsibility of the caller to ensure consistency is maintained
 * when using this function. The `upper_bound` is set to 1, so the caller is
 * responsible for ensuring that the `EncryptedAmount` is well-formed.
 */
export function setBalanceByIssuer(options: SetBalanceByIssuerOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null] satisfies (string | null)[];
	const parameterNames = ['t', 'account', 'newBalance'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'set_balance_by_issuer',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface IssueFreezeCapArguments {
	ct: RawTransactionArgument<string>;
	T: RawTransactionArgument<string>;
	addr: RawTransactionArgument<string>;
}
export interface IssueFreezeCapOptions {
	package?: string;
	arguments:
		| IssueFreezeCapArguments
		| [
				ct: RawTransactionArgument<string>,
				T: RawTransactionArgument<string>,
				addr: RawTransactionArgument<string>,
		  ];
	typeArguments: [string];
}
/**
 * Allow the given address to freeze the token globally or freeze individual
 * accounts (via the ManagementCap). Only the issuer can unfreeze (globally or
 * per-account). Aborts if the address already has the freeze capability.
 */
export function issueFreezeCap(options: IssueFreezeCapOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'address'] satisfies (string | null)[];
	const parameterNames = ['ct', 'T', 'addr'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'issue_freeze_cap',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface RevokeFreezeCapArguments {
	ct: RawTransactionArgument<string>;
	T: RawTransactionArgument<string>;
	addr: RawTransactionArgument<string>;
}
export interface RevokeFreezeCapOptions {
	package?: string;
	arguments:
		| RevokeFreezeCapArguments
		| [
				ct: RawTransactionArgument<string>,
				T: RawTransactionArgument<string>,
				addr: RawTransactionArgument<string>,
		  ];
	typeArguments: [string];
}
/**
 * Revoke the freeze capability from the given address. Aborts if the address does
 * not have the freeze capability.
 */
export function revokeFreezeCap(options: RevokeFreezeCapOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'address'] satisfies (string | null)[];
	const parameterNames = ['ct', 'T', 'addr'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'revoke_freeze_cap',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface GlobalFreezeArguments {
	ct: RawTransactionArgument<string>;
}
export interface GlobalFreezeOptions {
	package?: string;
	arguments: GlobalFreezeArguments | [ct: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Freeze the token globally. This prevents any transfers from happening until the
 * token is unfrozen again.
 */
export function globalFreeze(options: GlobalFreezeOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['ct'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'global_freeze',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface GlobalUnfreezeArguments {
	ct: RawTransactionArgument<string>;
	Cap: RawTransactionArgument<string>;
}
export interface GlobalUnfreezeOptions {
	package?: string;
	arguments:
		| GlobalUnfreezeArguments
		| [ct: RawTransactionArgument<string>, Cap: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Unfreeze the token globally. This allows transfers to happen again and can only
 * be done by the token issuer.
 */
export function globalUnfreeze(options: GlobalUnfreezeOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['ct', 'Cap'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'global_unfreeze',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface AccountFreezeArguments {
	ct: RawTransactionArgument<string>;
	account: RawTransactionArgument<string>;
}
export interface AccountFreezeOptions {
	package?: string;
	arguments:
		| AccountFreezeArguments
		| [ct: RawTransactionArgument<string>, account: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Freeze the given account for token `T`. A frozen account cannot transfer,
 * receive, wrap, or unwrap until unfrozen. Only addresses in `ct.freeze_admins`
 * may call this.
 */
export function accountFreeze(options: AccountFreezeOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['ct', 'account'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'account_freeze',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface AccountUnfreezeArguments {
	Cap: RawTransactionArgument<string>;
	account: RawTransactionArgument<string>;
}
export interface AccountUnfreezeOptions {
	package?: string;
	arguments:
		| AccountUnfreezeArguments
		| [Cap: RawTransactionArgument<string>, account: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Unfreeze the given account for token `T`. Only the token issuer (holder of
 * `&TreasuryCap<T>`) may call this. The asymmetry — admins freeze, only the issuer
 * unfreezes — mirrors `global_freeze` / `global_unfreeze`.
 */
export function accountUnfreeze(options: AccountUnfreezeOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['Cap', 'account'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'account_unfreeze',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface SetPolicyArguments {
	ct: RawTransactionArgument<string>;
	T: RawTransactionArgument<string>;
	permissionedOperations: RawTransactionArgument<Array<number>>;
}
export interface SetPolicyOptions {
	package?: string;
	arguments:
		| SetPolicyArguments
		| [
				ct: RawTransactionArgument<string>,
				T: RawTransactionArgument<string>,
				permissionedOperations: RawTransactionArgument<Array<number>>,
		  ];
	typeArguments: [string, string];
}
/**
 * Set a policy for the confidential token. This allows implementing permissioned
 * operations, but only the witness type is stored here - the logic must be handled
 * in the corresponding flows. See `register_permissioned` for an example of how
 * this can be implemented. Changing the witness type will break all in-flight
 * permissioned calls using the old witness, and thus highly discouraged.
 */
export function setPolicy(options: SetPolicyOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'vector<u8>'] satisfies (string | null)[];
	const parameterNames = ['ct', 'T', 'permissionedOperations'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'set_policy',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface UpdateAuditorArguments {
	ct: RawTransactionArgument<string>;
	Cap: RawTransactionArgument<string>;
	newPk: TransactionArgument;
	expirationEpoch: RawTransactionArgument<number | bigint>;
}
export interface UpdateAuditorOptions {
	package?: string;
	arguments:
		| UpdateAuditorArguments
		| [
				ct: RawTransactionArgument<string>,
				Cap: RawTransactionArgument<string>,
				newPk: TransactionArgument,
				expirationEpoch: RawTransactionArgument<number | bigint>,
		  ];
	typeArguments: [string];
}
/**
 * Update the auditor key for this confidential token. `new_pk` becomes the current
 * key (`none` disables auditing); the outgoing key is retained as the previous key,
 * valid for transfers through `expiration_epoch`.
 */
export function updateAuditor(options: UpdateAuditorOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null, 'u64'] satisfies (string | null)[];
	const parameterNames = ['ct', 'Cap', 'newPk', 'expirationEpoch'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'update_auditor',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
