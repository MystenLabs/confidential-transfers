// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Browser-safe helpers for publishing pre-compiled Move bytecodes and reading
 * back the resulting created objects. Compiling a Move package is a Node-only
 * operation; that lives in `./node.ts`.
 */

import type { ClientWithCoreApi, SuiClientTypes } from '@mysten/sui/client';
import type { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

export interface Bytecodes {
	modules: string[];
	dependencies: string[];
}

export interface CreatedObject {
	objectId: string;
	objectType: string;
}

export interface PublishResult {
	digest: string;
	packageId: string;
	createdObjects: CreatedObject[];
}

type ExecutedInclude = { effects: true; objectTypes: true };
export type ExecutedTransaction = SuiClientTypes.Transaction<ExecutedInclude>;

/** First created object whose `objectType` contains `typeMatch`. Throws if none. */
export function findObject(objects: CreatedObject[], typeMatch: string): string {
	const obj = objects.find((o) => o.objectType.includes(typeMatch));
	if (!obj) throw new Error(`No object found matching "${typeMatch}"`);
	return obj.objectId;
}

function assertSuccess(
	result: SuiClientTypes.TransactionResult<ExecutedInclude>,
	label: string,
): ExecutedTransaction {
	if (result.FailedTransaction) {
		throw new Error(
			`${label} failed: ${result.FailedTransaction.status.error?.message ?? 'unknown error'}`,
		);
	}
	return result.Transaction;
}

/**
 * Sign and execute `tx`, throw with `label` if it failed on chain, wait for
 * finality, and return the executed transaction (with effects and object
 * types included).
 */
export async function executeOrThrow(
	client: ClientWithCoreApi,
	tx: Transaction,
	signer: Ed25519Keypair,
	label = 'transaction',
): Promise<ExecutedTransaction> {
	const result = await client.core.signAndExecuteTransaction({
		transaction: tx,
		signer,
		include: { effects: true, objectTypes: true },
	});
	const executed = assertSuccess(result, label);
	await client.core.waitForTransaction({ result });
	return executed;
}

function createdObjects(tx: ExecutedTransaction): CreatedObject[] {
	return tx.effects.changedObjects
		.filter((c) => c.idOperation === 'Created' && c.outputState === 'ObjectWrite')
		.flatMap((c) => {
			const objectType = tx.objectTypes[c.objectId];
			return objectType ? [{ objectId: c.objectId, objectType }] : [];
		});
}

/**
 * Publish a bytecode bundle, transfer the upgrade cap to the publisher, and
 * wait for finality. Returns the published package id and every created
 * object as a `{objectId, objectType}` pair.
 */
export async function publishBytecodes(
	bytecodes: Bytecodes,
	keypair: Ed25519Keypair,
	client: ClientWithCoreApi,
): Promise<PublishResult> {
	const tx = new Transaction();
	const [upgradeCap] = tx.publish({
		modules: bytecodes.modules,
		dependencies: bytecodes.dependencies,
	});
	tx.transferObjects([upgradeCap], keypair.getPublicKey().toSuiAddress());

	const executed = await executeOrThrow(client, tx, keypair, 'publish');

	const packageId = executed.effects.changedObjects.find(
		(c) => c.outputState === 'PackageWrite',
	)?.objectId;
	if (!packageId) throw new Error('Failed to find published package');

	return {
		digest: executed.digest,
		packageId,
		createdObjects: createdObjects(executed),
	};
}

/** Sign and execute `tx` from `signer`, wait for finality, return the created objects. */
export async function signExecuteAndWait(
	tx: Transaction,
	signer: Ed25519Keypair,
	client: ClientWithCoreApi,
): Promise<CreatedObject[]> {
	return createdObjects(await executeOrThrow(client, tx, signer));
}
