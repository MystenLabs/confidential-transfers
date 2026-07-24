// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { DAppKitProvider } from '@mysten/dapp-kit-react';
import { Theme } from '@radix-ui/themes';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import App from './App';
import { dAppKit } from './dappKit';

import '@radix-ui/themes/styles.css';
import './index.css';

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById('root')!).render(
	<React.StrictMode>
		<Theme appearance="dark" accentColor="blue" radius="large">
			<QueryClientProvider client={queryClient}>
				<DAppKitProvider dAppKit={dAppKit}>
					<BrowserRouter>
						<App />
					</BrowserRouter>
				</DAppKitProvider>
			</QueryClientProvider>
		</Theme>
	</React.StrictMode>,
);
