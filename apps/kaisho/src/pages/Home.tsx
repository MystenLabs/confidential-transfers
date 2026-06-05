// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount } from '@mysten/dapp-kit';
import { useEffect, useMemo, useRef } from 'react';
import { Link, useParams } from 'react-router-dom';

import { Activity } from '../components/Activity';
import { EncKeySetup, useEncKey } from '../components/EncKeySetup';
import { WalletCard } from '../components/WalletCard';
import { useAccountStatus } from '../hooks/useAccountStatus';
import { useContraClient } from '../hooks/useContraClient';
import { useTokenConfig } from '../hooks/useTokenConfig';
import { contraPackageConfig, makeTokenAccount } from '../sdk';

export function Home() {
	const { configId } = useParams<{ configId: string }>();
	const account = useCurrentAccount();
	const prevAddress = useRef(account?.address);
	useEffect(() => {
		if (prevAddress.current && account?.address && prevAddress.current !== account.address) {
			window.location.reload();
		}
		prevAddress.current = account?.address;
	}, [account?.address]);

	const { config, isLoading, error } = useTokenConfig(configId!);
	const { encKey, saveKey } = useEncKey(configId, account?.address);

	const contraClient = useContraClient(config);
	const buTokenType = config ? `${config.buPackage}::bu::BU` : undefined;

	const tokenAccount = useMemo(() => {
		if (!account?.address || !buTokenType || !encKey || !config) return undefined;
		return makeTokenAccount(account.address, buTokenType, contraPackageConfig(config), encKey);
	}, [account?.address, buTokenType, encKey, config]);

	const {
		status: accountStatus,
		error: accountStatusError,
		refetch: refetchAccountStatus,
	} = useAccountStatus(contraClient, account?.address, buTokenType);

	if (isLoading) {
		return <p className="text-center text-gray-400">Loading token config…</p>;
	}

	if (error || !config) {
		return (
			<div className="card p-6 text-center">
				<p className="text-red-400">
					Failed to load TokenConfig <code className="text-xs break-all">{configId}</code>
				</p>
				{error && <p className="mt-2 text-sm text-gray-500">{String(error)}</p>}
				<Link to="/" className="btn-primary mt-4 inline-block">
					Create a New Deployment
				</Link>
			</div>
		);
	}

	if (!contraClient || !account) {
		return <p className="text-center text-gray-400">Loading…</p>;
	}

	return (
		<div className="flex flex-col gap-5">
			<EncKeySetup
				encKey={encKey}
				saveKey={saveKey}
				contraClient={contraClient}
				config={config}
				accountStatus={accountStatus}
				accountStatusError={accountStatusError}
				refetchAccountStatus={refetchAccountStatus}
				address={account.address}
				tokenType={buTokenType!}
			/>

			{encKey && (
				<>
					<WalletCard config={config} encKey={encKey} />
					<Activity config={config} tokenAccount={tokenAccount} />
				</>
			)}
		</div>
	);
}
