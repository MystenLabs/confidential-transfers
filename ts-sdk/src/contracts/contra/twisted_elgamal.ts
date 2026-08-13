/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';

const $moduleName = '@local-pkg/contra::twisted_elgamal';
export const PublicKey = new MoveStruct({
	name: `${$moduleName}::PublicKey`,
	fields: {
		element: group_ops.Element,
	},
});
export const Encryption = new MoveStruct({
	name: `${$moduleName}::Encryption`,
	fields: {
		ciphertext: group_ops.Element,
		decryption_handle: group_ops.Element,
	},
});
export interface NewArguments {
	ciphertext: TransactionArgument;
	decryptionHandle: TransactionArgument;
}
export interface NewOptions {
	package?: string;
	arguments:
		| NewArguments
		| [ciphertext: TransactionArgument, decryptionHandle: TransactionArgument];
}
/**
 * Create a new Twisted ElGamal encryption from a given `ciphertext` and
 * `decryption_handle`.
 */
export function _new(options: NewOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null] satisfies (string | null)[];
	const parameterNames = ['ciphertext', 'decryptionHandle'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'twisted_elgamal',
			function: 'new',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface PublicKeyArguments {
	element: TransactionArgument;
}
export interface PublicKeyOptions {
	package?: string;
	arguments: PublicKeyArguments | [element: TransactionArgument];
}
/**
 * Wrap `element` as a `PublicKey`, aborting with `EIdentityPublicKey` if it is the
 * group identity.
 */
export function publicKey(options: PublicKeyOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['element'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'twisted_elgamal',
			function: 'public_key',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface AsElementArguments {
	pk: TransactionArgument;
}
export interface AsElementOptions {
	package?: string;
	arguments: AsElementArguments | [pk: TransactionArgument];
}
/** The underlying group element. */
export function asElement(options: AsElementOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['pk'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'twisted_elgamal',
			function: 'as_element',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
