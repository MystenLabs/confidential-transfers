// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Browser-safe gRPC client construction for the public Sui fullnodes the
 * contra demos run against. Fullnode access is gRPC only — the JSON-RPC
 * API is deprecated.
 */

import { SuiGrpcClient } from '@mysten/sui/grpc';

/** Networks the contra demos can run against. */
export type ContraNetwork = 'devnet' | 'testnet';

const GRPC_FULLNODE_URLS: Record<ContraNetwork, string> = {
	devnet: 'https://fullnode.devnet.sui.io:443',
	testnet: 'https://fullnode.testnet.sui.io:443',
};

/** gRPC client for a public Sui fullnode on `network`. */
export function grpcClientFor(network: ContraNetwork): SuiGrpcClient {
	return new SuiGrpcClient({
		network,
		baseUrl: GRPC_FULLNODE_URLS[network],
	});
}
