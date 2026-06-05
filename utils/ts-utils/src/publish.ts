// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Browser-safe helpers for publishing pre-compiled Move bytecodes and reading
 * back the resulting object changes. Compiling a Move package is a Node-only
 * operation; that lives in `./node.ts`.
 */

import type { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import type { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

export interface Bytecodes {
	modules: string[];
	dependencies: string[];
}

export interface ObjectChange {
	type: string;
	objectId?: string;
	objectType?: string;
	packageId?: string;
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

/** Filter a transaction's `objectChanges` down to fully-populated `created` entries. */
export function filterCreated(changes: ObjectChange[]): CreatedObject[] {
	return changes.filter(
		(c): c is ObjectChange & CreatedObject =>
			c.type === 'created' && !!c.objectId && !!c.objectType,
	);
}

/** First created object whose `objectType` contains `typeMatch`. Throws if none. */
export function findObject(objects: CreatedObject[], typeMatch: string): string {
	const obj = objects.find((o) => o.objectType.includes(typeMatch));
	if (!obj) throw new Error(`No object found matching "${typeMatch}"`);
	return obj.objectId;
}

/**
 * Publish a bytecode bundle, transfer the upgrade cap to the publisher, and
 * wait for finality. Returns the published package id and every created
 * object as a `{objectId, objectType}` pair.
 */
export async function publishBytecodes(
	bytecodes: Bytecodes,
	keypair: Ed25519Keypair,
	client: SuiJsonRpcClient,
): Promise<PublishResult> {
	const tx = new Transaction();
	const [upgradeCap] = tx.publish({
		modules: bytecodes.modules,
		dependencies: bytecodes.dependencies,
	});
	tx.transferObjects([upgradeCap], keypair.getPublicKey().toSuiAddress());

	const result = await client.signAndExecuteTransaction({
		transaction: tx,
		signer: keypair,
		options: { showObjectChanges: true },
	});

	const changes = (result.objectChanges ?? []) as ObjectChange[];
	const published = changes.find((c) => c.type === 'published');
	if (!published?.packageId) throw new Error('Failed to find published package');

	await client.waitForTransaction({ digest: result.digest });

	return {
		digest: result.digest,
		packageId: published.packageId,
		createdObjects: filterCreated(changes),
	};
}

/** Sign and execute `tx` from `signer`, wait for finality, return objectChanges. */
export async function signExecuteAndWait(
	tx: Transaction,
	signer: Ed25519Keypair,
	client: SuiJsonRpcClient,
): Promise<ObjectChange[]> {
	const result = await client.signAndExecuteTransaction({
		transaction: tx,
		signer,
		options: { showObjectChanges: true },
	});
	await client.waitForTransaction({ digest: result.digest });
	return (result.objectChanges ?? []) as ObjectChange[];
}
