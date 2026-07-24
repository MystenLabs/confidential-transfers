// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { createDAppKit } from '@mysten/dapp-kit-react';

import { createGrpcClient, loadNetwork, SUPPORTED_NETWORKS, type Network } from './network';

export const dAppKit = createDAppKit({
	networks: [...SUPPORTED_NETWORKS],
	defaultNetwork: loadNetwork(),
	// The instance only ever passes networks from the list above.
	createClient: (network) => createGrpcClient(network as Network),
	autoConnect: true,
});

declare module '@mysten/dapp-kit-core' {
	interface Register {
		dAppKit: typeof dAppKit;
	}
}
