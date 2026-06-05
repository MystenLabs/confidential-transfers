// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

export default {
	printWidth: 100,
	semi: true,
	singleQuote: true,
	tabWidth: 2,
	trailingComma: 'all',
	useTabs: true,
	plugins: ['@ianvs/prettier-plugin-sort-imports'],
	overrides: [
		{
			files: '*.{ts,tsx}',
			options: {
				proseWrap: 'always',
				importOrder: [
					'<BUILT_IN_MODULES>',
					'<THIRD_PARTY_MODULES>',
					'',
					'^@/(.*)$',
					'^~/(.*)$',
					'',
					'^[.]',
				],
			},
		},
	],
};
