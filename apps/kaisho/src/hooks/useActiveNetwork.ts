// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useSuiClientContext } from '@mysten/dapp-kit';

import { DEFAULT_NETWORK, isNetwork, type Network } from '../network';

/**
 * The network kaisho is currently talking to, read from dapp-kit's
 * `SuiClientProvider` (the single source of truth). Components use this to
 * scope storage, build explorer links, and pick the right faucet/RPC.
 */
export function useActiveNetwork(): Network {
	const { network } = useSuiClientContext();
	return isNetwork(network) ? network : DEFAULT_NETWORK;
}
