// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useSuiClient } from '@mysten/dapp-kit';
import { useMemo } from 'react';
import type { ContraClient } from 'ts-sdk';

import { createContraClient } from '../sdk';
import type { TokenConfig } from '../sdk';
import { useDLogTable } from './useDLogTable';

export function useContraClient(config: TokenConfig | undefined): ContraClient | null {
	const suiClient = useSuiClient();
	const table = useDLogTable();

	return useMemo(() => {
		if (!config || !table) return null;
		return createContraClient(suiClient, config, table);
	}, [suiClient, table, config?.contraPackage, config?.accountRegistry, config?.tokenRegistry]);
}
