// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { createNetworkConfig } from '@mysten/dapp-kit';
import { getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc';

import { NETWORK } from './network';

const { networkConfig, useNetworkVariable } = createNetworkConfig({
	[NETWORK]: {
		network: NETWORK,
		url: getJsonRpcFullnodeUrl(NETWORK),
	},
});

export { networkConfig, useNetworkVariable };
