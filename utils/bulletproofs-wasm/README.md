# bulletproofs-wasm

WASM bindings around `fastcrypto::bulletproofs`.

## Prerequisites

- Rust toolchain with the wasm target: `rustup target add wasm32-unknown-unknown`
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/)
- macOS only: a wasm-capable clang — `brew install llvm`

## Build

```bash
pnpm build:wasm
```

On macOS, Apple's system clang has no wasm backend (a transitive C dependency, `blst`, is cross-compiled to wasm32), so point cc-rs at Homebrew's LLVM:

```bash
CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang AR_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/llvm-ar pnpm build:wasm
```

The `nodejs/` and `web/` outputs are gitignored build artifacts. After rebuilding, re-run `pnpm install --force` in `ts-sdk/` so the fresh outputs are re-packed.
