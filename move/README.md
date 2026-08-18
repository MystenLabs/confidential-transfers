# Move packages

This directory contains the Contra Move package and the separate canonical Guardian package under
[`guardian/`](guardian/), which can be deployed alongside Contra and enabled as its authority. See
the [top-level README](../README.md) for what they do.

## Prerequisites

- [Sui CLI](https://docs.sui.io/guides/developer/getting-started/sui-install)

## Build

```bash
sui move build -e devnet
sui move build -e devnet --path guardian
```

## Test

```bash
sui move test -e devnet           # run all tests
sui move test <filter> -e devnet  # run tests matching a name
sui move test -e devnet --path guardian
```

The `-e devnet` flag pins the build to the `devnet` environment defined in `Move.toml` and avoids a chain-ID mismatch error if your local Sui CLI is pointed at a devnet that has been wiped.
