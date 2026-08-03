/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';

const $moduleName = '@local-pkg/contra::twisted_elgamal';
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
