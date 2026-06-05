// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Node.js CommonJS entry. The wasm-pack `nodejs` build loads its `.wasm`
// synchronously at require, so `init` is a no-op kept only for API parity
// with the browser entry (which the `browser` export condition selects).
const wasm = require('./nodejs/contra_bulletproofs_wasm.js');
function init() {}
module.exports = init;
Object.assign(module.exports, wasm, { default: init });
