// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Config } from 'tailwindcss';

export default {
	content: ['./index.html', './src/**/*.{ts,tsx}'],
	darkMode: 'class',
	theme: {
		extend: {
			fontFamily: {
				sans: [
					'Outfit',
					'-apple-system',
					'BlinkMacSystemFont',
					'Segoe UI',
					'system-ui',
					'sans-serif',
				],
				mono: ['IBM Plex Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
			},
			colors: {
				surface: {
					DEFAULT: '#0c0d12',
					raised: 'rgba(255, 255, 255, 0.04)',
					hover: 'rgba(255, 255, 255, 0.07)',
				},
				accent: {
					DEFAULT: '#14b8a6',
					light: '#2dd4bf',
					dim: '#0d9488',
					glow: 'rgba(20, 184, 166, 0.15)',
				},
				border: {
					DEFAULT: 'rgba(255, 255, 255, 0.06)',
					hover: 'rgba(255, 255, 255, 0.12)',
					accent: 'rgba(20, 184, 166, 0.25)',
				},
			},
		},
	},
	plugins: [],
} satisfies Config;
