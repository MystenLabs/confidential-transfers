// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Node.js ESM entry. The wasm-pack `nodejs` build loads its `.wasm`
// synchronously at import, so `init` is a no-op kept only for API parity
// with the browser entry (which the `browser` export condition selects).
export * from './nodejs/contra_bulletproofs_wasm.js';
export default function init() {}
