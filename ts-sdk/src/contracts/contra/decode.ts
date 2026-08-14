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
export interface AuditorDecryptionHandlesArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface AuditorDecryptionHandlesOptions {
	package?: string;
	arguments:
		AuditorDecryptionHandlesArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
/**
 * Build one `[lo, hi]` handle pair per consecutive pair of point-encoded `parts`
 * (two u32-limb handles per transferred amount, flattened in amount order). Aborts
 * if `parts` has an odd length.
 */
export function auditorDecryptionHandles(options: AuditorDecryptionHandlesOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'auditor_decryption_handles',
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
export interface EncryptedAmountsArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface EncryptedAmountsOptions {
	package?: string;
	arguments: EncryptedAmountsArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
/**
 * Build one `EncryptedAmount` per 8 consecutive point-encoded `parts` (four limbs,
 * each a ciphertext + handle), in amount order. Aborts if `parts.length()` is not
 * a multiple of 8.
 */
export function encryptedAmounts(options: EncryptedAmountsOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'encrypted_amounts',
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
export interface ElgamalProofsArguments {
	parts: RawTransactionArgument<Array<Array<number>>>;
}
export interface ElgamalProofsOptions {
	package?: string;
	arguments: ElgamalProofsArguments | [parts: RawTransactionArgument<Array<Array<number>>>];
}
/**
 * Build one folded `ElGamalProof` per 4 consecutive parts (`a`, `b`, `z1`, `z2`),
 * in order. Aborts if `parts.length()` is not a multiple of 4.
 */
export function elgamalProofs(options: ElgamalProofsOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['parts'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'decode',
			function: 'elgamal_proofs',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
