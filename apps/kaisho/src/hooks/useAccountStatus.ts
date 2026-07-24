// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentClient } from '@mysten/dapp-kit-react';
import { useCallback, useEffect, useState } from 'react';
import type { ContraClient } from 'ts-sdk';

import { fetchAccountStatus } from '../sdk';
import type { AccountStatus } from '../sdk';

export type { AccountStatus } from '../sdk';

export function useAccountStatus(
	contraClient: ContraClient | null,
	address: string | undefined,
	tokenType: string | undefined,
) {
	const suiClient = useCurrentClient();
	const [status, setStatus] = useState<AccountStatus>('loading');
	const [error, setError] = useState<Error | undefined>();

	const check = useCallback(async () => {
		if (!contraClient || !address || !tokenType) return;
		setStatus('loading');
		setError(undefined);
		try {
			const next = await fetchAccountStatus(contraClient, suiClient, address, tokenType);
			setStatus(next);
		} catch (e) {
			setError(e instanceof Error ? e : new Error(String(e)));
			setStatus('error');
		}
	}, [contraClient, address, tokenType, suiClient]);

	useEffect(() => {
		check();
	}, [check]);

	return { status, error, refetch: check };
}
