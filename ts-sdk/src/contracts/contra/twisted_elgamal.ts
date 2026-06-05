/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';

const $moduleName = '@local-pkg/contra::twisted_elgamal';
export const MultiRecipientEncryption = new MoveStruct({
	name: `${$moduleName}::MultiRecipientEncryption`,
	fields: {
		ciphertext: group_ops.Element,
		decryption_handles: bcs.vector(group_ops.Element),
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
export interface NewMultiRecipientEncryptionArguments {
	ciphertext: TransactionArgument;
	decryptionHandles: TransactionArgument;
}
export interface NewMultiRecipientEncryptionOptions {
	package?: string;
	arguments:
		| NewMultiRecipientEncryptionArguments
		| [ciphertext: TransactionArgument, decryptionHandles: TransactionArgument];
}
/**
 * Construct a Twisted ElGamal `MultiRecipientEncryption` consisting of a shared
 * ciphertext `c = r * g + m * h` and one decryption handle `d_i = r * pk_i` per
 * recipient identified by their public key `pk_i`.
 */
export function newMultiRecipientEncryption(options: NewMultiRecipientEncryptionOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, 'vector<null>'] satisfies (string | null)[];
	const parameterNames = ['ciphertext', 'decryptionHandles'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'twisted_elgamal',
			function: 'new_multi_recipient_encryption',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface MultiRecipientCiphertextArguments {
	e: TransactionArgument;
}
export interface MultiRecipientCiphertextOptions {
	package?: string;
	arguments: MultiRecipientCiphertextArguments | [e: TransactionArgument];
}
/**
 * Returns the shared ciphertext component `c = r * g + m * h` of a Twisted ElGamal
 * `MultiRecipientEncryption`.
 */
export function multiRecipientCiphertext(options: MultiRecipientCiphertextOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['e'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'twisted_elgamal',
			function: 'multi_recipient_ciphertext',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface MultiRecipientDecryptionHandlesArguments {
	e: TransactionArgument;
}
export interface MultiRecipientDecryptionHandlesOptions {
	package?: string;
	arguments: MultiRecipientDecryptionHandlesArguments | [e: TransactionArgument];
}
/**
 * Returns the per-recipient decryption handles `d_i = r * pk_i` for recipient
 * public key `pk_i` of a Twisted ElGamal `MultiRecipientEncryption`.
 */
export function multiRecipientDecryptionHandles(options: MultiRecipientDecryptionHandlesOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['e'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'twisted_elgamal',
			function: 'multi_recipient_decryption_handles',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
