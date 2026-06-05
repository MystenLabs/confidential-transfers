// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared setup for the devnet e2e suite. `createHarness` publishes the contra
 * package and a fresh test token, builds a `ContraClient`, configures a
 * baseline two-auditor set, and bundles in the shared transaction helpers
 * from `operations.ts`.
 */

import { join } from 'node:path';
import { ContraInitializer } from 'contra-utils/node';

import { contra } from '../../src/client.js';
import { DiscreteLogTable } from '../../src/twisted_elgamal.js';
import { createOperations } from './operations.js';
import type { ContraTestClient } from './operations.js';
import { TokenIssuer } from './token_issuer.js';

// Re-export the operations API so suites only need to import from `harness.ts`.
export { createOperations, FUNDING_AMOUNT, ONE } from './operations.js';
export type {
	ContraTestClient,
	ExpectedBalance,
	FreshUser,
	Operations,
	Signer,
} from './operations.js';

/**
 * Deploy the contra package and a fresh confidential test token, build a
 * `ContraClient`, configure a baseline two-auditor set, and return the
 * context plus the shared transaction helpers.
 */
export async function createHarness() {
	const contraInit = await ContraInitializer.init({
		contraMoveDir: join(import.meta.dirname, '..', '..', '..', 'move'),
	});
	const tokenIssuer = await TokenIssuer.init(contraInit);
	const table = DiscreteLogTable.create(16);
	const packageConfig = {
		packageId: contraInit.contraPackageId,
		accountRegistryId: contraInit.accountRegistryId,
		tokenRegistryId: contraInit.tokenRegistryId,
	};

	const client: ContraTestClient = contraInit.client.$extend(contra({ packageConfig, table }));

	// Baseline: two auditor keys configured for the token.
	await tokenIssuer.rotateAuditorKeys(2);

	return {
		contraInit,
		tokenIssuer,
		client,
		packageConfig,
		table,
		...createOperations(contraInit, tokenIssuer, client, packageConfig),
	};
}

/** The context + helpers returned by `createHarness`. */
export type Harness = Awaited<ReturnType<typeof createHarness>>;
