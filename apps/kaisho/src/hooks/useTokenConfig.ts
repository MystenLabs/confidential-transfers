// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentClient } from '@mysten/dapp-kit-react';
import { useQuery } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';

import { nsKey, type Network } from '../network';
import { fetchTokenConfig } from '../sdk';
import type { TokenConfig } from '../sdk';
import { useActiveNetwork } from './useActiveNetwork';

export type { TokenConfig } from '../sdk';

const STORAGE_KEY = 'kaisho_token_configs';

function getCache(network: Network): Record<string, TokenConfig> {
	try {
		return JSON.parse(localStorage.getItem(nsKey(STORAGE_KEY, network)) || '{}');
	} catch {
		return {};
	}
}

function setCache(id: string, config: TokenConfig, network: Network) {
	const cache = getCache(network);
	cache[id] = config;
	localStorage.setItem(nsKey(STORAGE_KEY, network), JSON.stringify(cache));
}

function digestsEqual(a: number[], b: number[]): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

function digestHex(d: number[]): string {
	return d.map((b) => b.toString(16).padStart(2, '0')).join('');
}

let expectedDigestPromise: Promise<number[]> | null = null;

function fetchExpectedDigest(): Promise<number[]> {
	if (!expectedDigestPromise) {
		expectedDigestPromise = fetch('/bu_token_bytecodes.json')
			.then((r) => r.json())
			.then((j: { digest: number[] }) => j.digest);
	}
	return expectedDigestPromise;
}

export function useTokenConfig(configId: string) {
	const network = useActiveNetwork();
	// Treat pre-digest cache entries as a miss so we re-fetch and validate.
	const cached = useMemo(() => {
		const entry = getCache(network)[configId];
		if (!entry || !Array.isArray(entry.binaryDigest) || entry.binaryDigest.length === 0) {
			return undefined;
		}
		return entry;
	}, [configId, network]);

	const suiClient = useCurrentClient();
	const { data, isLoading, error } = useQuery({
		queryKey: ['token-config', network, configId],
		enabled: !cached,
		queryFn: () => fetchTokenConfig(suiClient, configId),
	});

	const config = cached ?? data ?? undefined;

	useEffect(() => {
		if (config && !cached) {
			setCache(configId, config, network);
		}
	}, [config, cached, configId, network]);

	const [digestError, setDigestError] = useState<Error | undefined>();
	useEffect(() => {
		if (!config) return;
		let cancelled = false;
		fetchExpectedDigest()
			.then((expected) => {
				if (cancelled) return;
				if (!digestsEqual(config.binaryDigest, expected)) {
					setDigestError(
						new Error(
							`TokenConfig was created from a different Move build than the one this app was built from. ` +
								`On-chain digest: ${digestHex(config.binaryDigest)}, expected: ${digestHex(expected)}. ` +
								`Re-deploy the contracts to get a fresh TokenConfig.`,
						),
					);
				} else {
					setDigestError(undefined);
				}
			})
			.catch((e) => {
				if (!cancelled) setDigestError(e instanceof Error ? e : new Error(String(e)));
			});
		return () => {
			cancelled = true;
		};
	}, [config]);

	return {
		config: digestError ? undefined : config,
		isLoading: !cached && isLoading,
		error: error ?? digestError,
	};
}
