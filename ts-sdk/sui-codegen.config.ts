// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { SuiCodegenConfig } from '@mysten/codegen';

const config: SuiCodegenConfig = {
	output: './src/contracts',
	// Pre-generate summaries with `sui move summary -e devnet` from the move
	// dir — the codegen tool's own `sui move summary` call doesn't know about
	// the `devnet` environment, which is required to resolve `sui::rangeproofs`.
	generateSummaries: false,
	packages: [
		{
			package: '@local-pkg/contra',
			path: '../move',
		},
		{
			// `dynamic_field` is used to parse the on-chain `Field<TokenAccountKey<T>,
			// TokenAccount<T>>` wrapper around per-token account state. We point
			// at the same `move/` summaries that the contra dep on Sui already
			// produces, instead of pulling Sui over the network.
			package: '0x0000000000000000000000000000000000000000000000000000000000000002',
			packageName: 'sui',
			path: '../move',
			generate: {
				modules: ['dynamic_field'],
				functions: false,
			},
		},
	],
};

export default config;
