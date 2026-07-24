// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentNetwork } from '@mysten/dapp-kit-react';

import { DEFAULT_NETWORK, isNetwork, type Network } from '../network';

/**
 * The network kaisho is currently talking to, read from the dapp-kit
 * instance (the single source of truth). Components use this to scope
 * storage, build explorer links, and pick the right faucet/RPC.
 */
export function useActiveNetwork(): Network {
	const network = useCurrentNetwork();
	return isNetwork(network) ? network : DEFAULT_NETWORK;
}
