// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { createNetworkConfig } from '@mysten/dapp-kit';
import { getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc';

const { networkConfig, useNetworkVariable } = createNetworkConfig({
	devnet: {
		network: 'devnet',
		url: getJsonRpcFullnodeUrl('devnet'),
	},
});

export { networkConfig, useNetworkVariable };
