// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useDAppKit } from '@mysten/dapp-kit-react';
import type { Transaction } from '@mysten/sui/transactions';
import { useCallback } from 'react';

/**
 * Sign and execute a transaction with the connected wallet. Throws when the
 * transaction executed but failed on chain, so callers only handle the happy
 * path plus a single error branch.
 */
export function useSignAndExecute() {
	const dAppKit = useDAppKit();
	return useCallback(
		async ({ transaction }: { transaction: Transaction }): Promise<{ digest: string }> => {
			const result = await dAppKit.signAndExecuteTransaction({ transaction });
			if (result.FailedTransaction) {
				throw new Error(result.FailedTransaction.status.error?.message ?? 'Transaction failed');
			}
			return { digest: result.Transaction.digest };
		},
		[dAppKit],
	);
}
