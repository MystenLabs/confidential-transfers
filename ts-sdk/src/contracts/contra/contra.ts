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
 * 6.  Rotate, enable, or disable the auditor keys via `update_auditors` (using the
 *     ManagementCap), which sets the parallel `current_pks` / `previous_pks` key
 *     vectors. A transfer is accepted under either set, so pointing `current_pks`
 *     at new keys while `previous_pks` still holds the outgoing keys gives a grace
 *     window for in-flight transfers; passing empty `current_pks` disables
 *     auditing. Auditing is per-transfer and each transfer carries
 *     auditor-readable ciphertexts of the amount, one set per auditor key.
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
 * 1.  Create an account for an address (permissionless, needed once for all token
 *     types). Optionally set a default key later (`set_default_pk_as_sender`) so
 *     others can auto-register tokens for you via `register_with_default_pk`.
 * 2.  Register a token account for a token type `T` under a key of your choice
 *     (`register`). Per-token keys are independent of the account's default key.
 * 3.  Rotate a token's key with `rekey_token_account` (to any `new_pk`), and
 *     set/clear the account's default key with `set_default_pk_as_sender`.
 * 4.  Wrap a public coin into a confidential token, adding to the pending
 *     encrypted balance of an account.
 * 5.  Transfer an encrypted amount to one or more token accounts. Every receiver
 *     must already have a `TokenAccount<T>`; for permissionless tokens anyone can
 *     create one on their behalf up front with `register_with_default_pk`. Auditor
 *     data is attached if set.
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
import * as twisted_elgamal from './twisted_elgamal.js';

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
		auditors: auditors.Auditors,
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
		default_pk: bcs.option(twisted_elgamal.PublicKey),
	},
});
export const TokenAccount = new MoveStruct({
	name: `${$moduleName}::TokenAccount<phantom T>`,
	fields: {
		session_id: bcs.vector(bcs.u8()),
		is_frozen: bcs.bool(),
		accepts_deposits: bcs.bool(),
		balance: balance.EncryptedBalance,
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
				sender_pk: twisted_elgamal.PublicKey,
				coins: bcs.vector(balance.EncryptedCoin),
				seed_point: group_ops.Element,
				next_index: bcs.u8(),
				auditor_data: bcs.option(auditors.VerifiedAuditorHandles),
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
		string | null
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
	auditorPublicKeys: TransactionArgument;
}
export interface NewConfidentialTokenOptions {
	package?: string;
	arguments:
		| NewConfidentialTokenArguments
		| [
				registry: RawTransactionArgument<string>,
				T: RawTransactionArgument<string>,
				auditorPublicKeys: TransactionArgument,
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
 * Sets the token's auditor keys to `auditor_public_keys` (per-transfer auditing);
 * every transfer will carry one auditor-readable ciphertext set per key. Pass an
 * empty vector to start with auditing disabled. The issuer can enable, rotate, or
 * disable the keys later via `update_auditors`.
 *
 * Returns the created `ConfidentialToken` and a `ManagementCap` that can be used
 * to perform administrative operations for this token.
 */
export function newConfidentialToken(options: NewConfidentialTokenOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'vector<null>'] satisfies (string | null)[];
	const parameterNames = ['registry', 'T', 'auditorPublicKeys'];
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
}
export interface NewAccountOptions {
	package?: string;
	arguments:
		| NewAccountArguments
		| [registry: RawTransactionArgument<string>, owner: RawTransactionArgument<string>];
}
/**
 * Create a new account owned by `owner`, with no default key set (set one later
 * with `set_default_pk_as_sender` / `set_default_pk_as_object`). Permissionless:
 * anyone can create the account for any owner — it only reserves the owner's
 * derived slot and sets no key. Aborts if `owner` already has an account.
 */
export function newAccount(options: NewAccountOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, 'address'] satisfies (string | null)[];
	const parameterNames = ['registry', 'owner'];
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
	pk: TransactionArgument;
}
export interface RegisterOptions {
	package?: string;
	arguments:
		| RegisterArguments
		| [account: RawTransactionArgument<string>, auth: TransactionArgument, pk: TransactionArgument];
	typeArguments: [string];
}
/**
 * Create a `TokenAccount` for token `T`, with its balances keyed under `pk`.
 * Authorized by `auth`, which must be for the `PERMISSIONED_REGISTER` operation
 * and for `account.owner`.
 */
export function register(options: RegisterOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'pk'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'register',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface RegisterWithDefaultPkArguments {
	account: RawTransactionArgument<string>;
	ct: RawTransactionArgument<string>;
}
export interface RegisterWithDefaultPkOptions {
	package?: string;
	arguments:
		| RegisterWithDefaultPkArguments
		| [account: RawTransactionArgument<string>, ct: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Permissionless `register`: create a `TokenAccount<T>` keyed under the account's
 * `default_pk`, without any `Auth`. Requires `T`'s registration permissionless and
 * `default_pk` set.
 */
export function registerWithDefaultPk(options: RegisterWithDefaultPkOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'ct'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'register_with_default_pk',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface TryRegisterWithDefaultPkArguments {
	account: RawTransactionArgument<string>;
	ct: RawTransactionArgument<string>;
}
export interface TryRegisterWithDefaultPkOptions {
	package?: string;
	arguments:
		| TryRegisterWithDefaultPkArguments
		| [account: RawTransactionArgument<string>, ct: RawTransactionArgument<string>];
	typeArguments: [string];
}
/**
 * Like `register_with_default_pk`, but a no-op if `account` already has a
 * `TokenAccount<T>`.
 */
export function tryRegisterWithDefaultPk(options: TryRegisterWithDefaultPkOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'ct'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'try_register_with_default_pk',
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
export interface SetDefaultPkAsSenderArguments {
	account: RawTransactionArgument<string>;
	defaultPk: TransactionArgument;
}
export interface SetDefaultPkAsSenderOptions {
	package?: string;
	arguments:
		| SetDefaultPkAsSenderArguments
		| [account: RawTransactionArgument<string>, defaultPk: TransactionArgument];
}
/**
 * Set the account's optional `default_pk` (pass `none` to clear it, which disables
 * permissionless auto-registration).
 */
export function setDefaultPkAsSender(options: SetDefaultPkAsSenderOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['account', 'defaultPk'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'set_default_pk_as_sender',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface SetDefaultPkAsObjectArguments {
	account: RawTransactionArgument<string>;
	defaultPk: TransactionArgument;
	uid: RawTransactionArgument<string>;
}
export interface SetDefaultPkAsObjectOptions {
	package?: string;
	arguments:
		| SetDefaultPkAsObjectArguments
		| [
				account: RawTransactionArgument<string>,
				defaultPk: TransactionArgument,
				uid: RawTransactionArgument<string>,
		  ];
}
/**
 * Set the `default_pk` of an account owned by the object identified by `uid`.
 * Holding `&mut UID` proves custody of the object, so it self-authenticates as its
 * own owner.
 */
export function setDefaultPkAsObject(options: SetDefaultPkAsObjectOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, '0x2::object::ID'] satisfies (string | null)[];
	const parameterNames = ['account', 'defaultPk', 'uid'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'set_default_pk_as_object',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface RekeyTokenAccountArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	newPk: TransactionArgument;
	newHandles: TransactionArgument;
	rekeyProof: TransactionArgument;
}
export interface RekeyTokenAccountOptions {
	package?: string;
	arguments:
		| RekeyTokenAccountArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				newPk: TransactionArgument,
				newHandles: TransactionArgument,
				rekeyProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Re-key token `T`'s active balance from its current `TokenAccount.pk` to
 * `new_pk`, swapping each limb's decryption handle for the matching
 * `new_handles[i]` (proven by `rekey_proof`). `new_pk` is explicit and independent
 * of the account's default key. Aborts if the token has unmerged pending deposits
 * (which are under the old key, so they must be merged first) or the proof fails.
 * Authorized by `auth`, which must be for the `PERMISSIONED_REGISTER` operation
 * and for `account.owner`.
 */
export function rekeyTokenAccount(options: RekeyTokenAccountOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null, 'vector<null>', null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'newPk', 'newHandles', 'rekeyProof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'rekey_token_account',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
export interface TryRekeyTokenAccountAndUnpauseArguments {
	account: RawTransactionArgument<string>;
	auth: TransactionArgument;
	newPk: TransactionArgument;
	newHandles: TransactionArgument;
	rekeyProof: TransactionArgument;
}
export interface TryRekeyTokenAccountAndUnpauseOptions {
	package?: string;
	arguments:
		| TryRekeyTokenAccountAndUnpauseArguments
		| [
				account: RawTransactionArgument<string>,
				auth: TransactionArgument,
				newPk: TransactionArgument,
				newHandles: TransactionArgument,
				rekeyProof: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Like `rekey_token_account` but soft-fails instead of aborting if the re-key
 * proof does not verify (e.g. a deposit raced the caller's read). The re-key flow
 * pauses the token first (`accepts_deposits  = false`) so no deposit lands under
 * the old key mid-rotation; on success this re-keys the token and resumes deposits
 * (`accepts_deposits = true`), now under the new key. On failure it emits
 * `TryTokenRekeyFailedEvent` and leaves the token unchanged (still paused) for a
 * retry. Still aborts on unmerged pending deposits.
 */
export function tryRekeyTokenAccountAndUnpause(options: TryRekeyTokenAccountAndUnpauseOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null, 'vector<null>', null] satisfies (string | null)[];
	const parameterNames = ['account', 'auth', 'newPk', 'newHandles', 'rekeyProof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'try_rekey_token_account_and_unpause',
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
	receiverEncsPok: TransactionArgument;
	newBalance: TransactionArgument;
	totalSenderHandle: TransactionArgument;
	senderEncsPok: TransactionArgument;
	rangeProofs: TransactionArgument;
	seedPoint: TransactionArgument;
	balanceProof: TransactionArgument;
	auditorPackage: TransactionArgument;
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
				receiverEncsPok: TransactionArgument,
				newBalance: TransactionArgument,
				totalSenderHandle: TransactionArgument,
				senderEncsPok: TransactionArgument,
				rangeProofs: TransactionArgument,
				seedPoint: TransactionArgument,
				balanceProof: TransactionArgument,
				auditorPackage: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Initiate a batched transfer from `sender` to multiple receivers.
 *
 * `receiver_amounts[i]` is the transferred value re-encrypted under
 * `receiver_pks[i]` and proven valid by `receiver_encs_pok[i]`; `sender_encs_pok`
 * folds the `new_balance` limbs and the transfer total (under `sender`'s key) into
 * one proof; `range_proofs` range-check every limb; and `total_sender_handle` is
 * the single sender-keyed decryption handle for the total (its commitment is
 * reconstructed on chain from the receiver amounts). The amounts are verified
 * against `sender`'s own key and session (see `verify_transfer_amounts`), so they
 * are bound to this transfer by construction. `balance_proof` proves the sender's
 * balance drops by exactly the transfer total (see `balance::try_withdraw_batch`).
 * `seed_point` (= `P`) is forwarded to the events so the sender can re-derive each
 * transfer's blinding and recover its outgoing amounts; it is not otherwise
 * verified on chain.
 *
 * Per-transfer auditing: when `ct` has auditor keys enabled, `auditor_package`
 * must be `some`. See `auditors::verify_transfer` for details.
 *
 * Returns `TransferBatch::Ok` when `balance_proof` verifies, else
 * `BalanceProofFailed`. Aborts if a proof or the auditor requirement fails. Call
 * `add` once per receiver, in `receiver_amounts` order, then `finalize`.
 * Authorized by any `Auth<T>` for `sender.owner`.
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
		'vector<null>',
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
		'receiverEncsPok',
		'newBalance',
		'totalSenderHandle',
		'senderEncsPok',
		'rangeProofs',
		'seedPoint',
		'balanceProof',
		'auditorPackage',
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
 * `EncryptedCoin` and credit it to the receiver's pending deposits. The receiver
 * must already have a `TokenAccount<T>` (for permissionless tokens anyone can
 * create one up front with `register_with_default_pk`). Aborts if:
 *
 * - the receiver has no `TokenAccount<T>`,
 * - the receiver is frozen or on the deny list,
 * - `add_to_batch` is called more times than there were `receiver_amounts` in
 *   `batched_transfer`,
 * - the coin is not encrypted under the receiver's public key.
 */
export function addToBatch(options: AddToBatchOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'vector<u8>', '0x2::deny_list::DenyList'] satisfies (
		string | null
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
	newBalancePok: TransactionArgument;
	newBalanceRangeProofs: TransactionArgument;
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
				newBalancePok: TransactionArgument,
				newBalanceRangeProofs: TransactionArgument,
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
	const argumentsTypes = [null, null, null, null, null, null] satisfies (string | null)[];
	const parameterNames = [
		'account',
		'auth',
		'newBalance',
		'newBalancePok',
		'newBalanceRangeProofs',
		'balanceProof',
	];
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
	newBalanceConsistencyProof: TransactionArgument;
	newBalanceRangeProofs: TransactionArgument;
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
				newBalanceConsistencyProof: TransactionArgument,
				newBalanceRangeProofs: TransactionArgument,
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
		'newBalanceConsistencyProof',
		'newBalanceRangeProofs',
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
	newBalanceConsistencyProof: TransactionArgument;
	newBalanceRangeProofs: TransactionArgument;
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
				newBalanceConsistencyProof: TransactionArgument,
				newBalanceRangeProofs: TransactionArgument,
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
		'newBalanceConsistencyProof',
		'newBalanceRangeProofs',
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
	T: RawTransactionArgument<string>;
	account: RawTransactionArgument<string>;
	newBalance: TransactionArgument;
}
export interface SetBalanceByIssuerOptions {
	package?: string;
	arguments:
		| SetBalanceByIssuerArguments
		| [
				T: RawTransactionArgument<string>,
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
 * responsible for ensuring that the `EncryptedAmount` is in range.
 */
export function setBalanceByIssuer(options: SetBalanceByIssuerOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null] satisfies (string | null)[];
	const parameterNames = ['T', 'account', 'newBalance'];
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
export interface UpdateAuditorsArguments {
	ct: RawTransactionArgument<string>;
	Cap: RawTransactionArgument<string>;
	currentPks: TransactionArgument;
	previousPks: TransactionArgument;
}
export interface UpdateAuditorsOptions {
	package?: string;
	arguments:
		| UpdateAuditorsArguments
		| [
				ct: RawTransactionArgument<string>,
				Cap: RawTransactionArgument<string>,
				currentPks: TransactionArgument,
				previousPks: TransactionArgument,
		  ];
	typeArguments: [string];
}
/**
 * Replace this confidential token's auditor keys. `current_pks` is tried first
 * when verifying a transfer, then `previous_pks`. The two do not have to be the
 * same length. The caller can drive a grace policy: rotate with
 * `update_auditors(new, old_current)` and end the grace with
 * `update_auditors(new, [])`.
 */
export function updateAuditors(options: UpdateAuditorsOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, 'vector<null>', 'vector<null>'] satisfies (string | null)[];
	const parameterNames = ['ct', 'Cap', 'currentPks', 'previousPks'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'contra',
			function: 'update_auditors',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
			typeArguments: options.typeArguments,
		});
}
