// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { type SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { type Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeStructTag, SUI_FRAMEWORK_ADDRESS } from '@mysten/sui/utils';
import {
	compileMovePackage,
	ContraInitializer,
	filterCreated,
	findObject,
	patchPublishedToml,
	publishBytecodes,
	signExecuteAndWait,
} from 'contra-utils/node';
import { type ContraPackageConfig } from 'ts-sdk';

import { type PaymentChannelPackageConfig } from './client.ts';

/**
 * IDs returned by {@link deployBundle} — everything a demo needs to interact
 * with the freshly published bu_token + contra + payment_channel packages.
 *
 * Contra is published on its own (so its package id is stable and
 * Published.toml-recordable). bu_token and payment_channel are bundled into
 * a second publish, so they share `packageId` and that id is also where the
 * `BU` type and the `payment_channel` module live.
 */
export type Deployment = {
	contraInit: ContraInitializer;
	packageId: string;
	contra: ContraPackageConfig;
	paymentChannel: PaymentChannelPackageConfig;
	buType: string;
	buTreasuryId: string;
	confidentialTokenId: string;
	poolId: string;
};

function repoRoot(): string {
	return resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
}

function paymentChannelMoveDir(): string {
	return resolve(repoRoot(), 'apps/payment-channel/move/payment_channel');
}

function contraMoveDir(): string {
	return resolve(repoRoot(), 'move');
}

/**
 * Two-step deploy:
 *   1. Publish `contra` via {@link ContraInitializer} (its own package id).
 *   2. Patch contra's `Published.toml` to point at the just-published id,
 *      then compile + publish `payment_channel` bundled with `bu_token` —
 *      they share a second package id and link to the published contra by
 *      its `Published.toml` address.
 *
 * After step 2 the patched `Published.toml` is restored so the working tree
 * is left clean.
 */
export async function deployBundle(opts: {
	suiClient: SuiJsonRpcClient;
	deployer: Ed25519Keypair;
}): Promise<Deployment> {
	const contraInit = await ContraInitializer.init({ contraMoveDir: contraMoveDir() });

	const restore = patchPublishedToml(contraMoveDir(), contraInit.contraPackageId);
	let bytecodes;
	try {
		bytecodes = compileMovePackage(paymentChannelMoveDir(), { withUnpublishedDeps: true });
	} finally {
		restore();
	}
	const { packageId, createdObjects } = await publishBytecodes(
		bytecodes,
		opts.deployer,
		opts.suiClient,
	);

	const buTreasuryId = findObject(createdObjects, `${packageId}::bu::BuTreasury`);
	const buType = normalizeStructTag(`${packageId}::bu::BU`);

	const contra: ContraPackageConfig = {
		packageId: contraInit.contraPackageId,
		accountRegistryId: contraInit.accountRegistryId,
		tokenRegistryId: contraInit.tokenRegistryId,
	};

	const regTx = new Transaction();
	regTx.moveCall({
		target: `${packageId}::bu::register_confidential`,
		arguments: [
			regTx.object(buTreasuryId),
			regTx.object(contra.tokenRegistryId),
			regTx.makeMoveVec({
				type: `${SUI_FRAMEWORK_ADDRESS}::group_ops::Element<${SUI_FRAMEWORK_ADDRESS}::ristretto255::G>`,
				elements: [],
			}),
		],
	});
	const regChanges = await signExecuteAndWait(regTx, opts.deployer, opts.suiClient);
	const regCreated = filterCreated(regChanges);
	const confidentialTokenId = findObject(
		regCreated,
		`${contra.packageId}::contra::ConfidentialToken<`,
	);
	const poolId = findObject(regCreated, `${contra.packageId}::contra::Pool<`);

	const paymentChannel: PaymentChannelPackageConfig = {
		paymentChannelPackageId: packageId,
		contra,
	};

	return {
		contraInit,
		packageId,
		contra,
		paymentChannel,
		buType,
		buTreasuryId,
		confidentialTokenId,
		poolId,
	};
}
