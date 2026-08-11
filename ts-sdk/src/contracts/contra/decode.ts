/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * Simple deserialization functions that build the composite crypto types from
 * their byte-encoded elements in a single Move call.
 */

import { type Transaction } from '@mysten/sui/transactions';

import { normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';

export interface GVectorArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface GVectorOptions {
	package?: string;
	arguments: GVectorArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
export function gVector(options: GVectorOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'g_vector',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface PublicKeysArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface PublicKeysOptions {
	package?: string;
	arguments: PublicKeysArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
/**
 * Build one `PublicKey` per point-encoded part; each is validated non-identity by
 * `public_key`.
 */
export function publicKeys(options: PublicKeysOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'public_keys',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface DecryptionHandlesArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface DecryptionHandlesOptions {
	package?: string;
	arguments: DecryptionHandlesArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
/**
 * Build one `DecryptionHandles` per consecutive pair of point-encoded `parts` (two
 * u32-limb handles per transferred amount, flattened in amount order). Aborts if
 * `parts` has an odd length.
 */
export function decryptionHandles(options: DecryptionHandlesOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'decryption_handles',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface EncryptionArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface EncryptionOptions {
	package?: string;
	arguments: EncryptionArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
export function encryption(options: EncryptionOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'encryption',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface EncryptedAmountArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface EncryptedAmountOptions {
	package?: string;
	arguments: EncryptedAmountArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
export function encryptedAmount(options: EncryptedAmountOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'encrypted_amount',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface DdhProofArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface DdhProofOptions {
	package?: string;
	arguments: DdhProofArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
export function ddhProof(options: DdhProofOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'ddh_proof',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface ElgamalProofArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface ElgamalProofOptions {
	package?: string;
	arguments: ElgamalProofArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
export function elgamalProof(options: ElgamalProofOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'elgamal_proof',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface MultiKeyElgamalProofArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface MultiKeyElgamalProofOptions {
	package?: string;
	arguments: MultiKeyElgamalProofArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
/**
 * Build a `MultiKeyElGamalProof` from `[a_0, …, a_{m-1}, b, z1, z2]`: the leading
 * `parts.length - 3` point-encoded entries are the per-key handle masks `a`,
 * followed by the point `b` and the two scalars `z1, z2`.
 */
export function multiKeyElgamalProof(options: MultiKeyElgamalProofOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'multi_key_elgamal_proof',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
