// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ConnectButton, useCurrentAccount } from '@mysten/dapp-kit';

export function WalletGuard({ children }: { children: React.ReactNode }) {
	const account = useCurrentAccount();

	if (!account) {
		return (
			<div className="flex flex-col items-center gap-8 pt-32">
				<div className="flex flex-col items-center gap-3">
					<h2 className="text-2xl font-semibold tracking-tight text-white">Welcome to Kaisho</h2>
					<p className="text-sm text-zinc-500">Confidential transfers on Sui</p>
				</div>
				<ConnectButton />
			</div>
		);
	}

	return <>{children}</>;
}
