# Move package

On-chain Move modules for the project. See the [top-level README](../README.md) for what they do.

## Prerequisites

- [Sui CLI](https://docs.sui.io/guides/developer/getting-started/sui-install)

## Build

```bash
sui move build -e devnet
```

## Test

```bash
sui move test -e devnet           # run all tests
sui move test <filter> -e devnet  # run tests matching a name
```

The `-e devnet` flag pins the build to the `devnet` environment defined in `Move.toml` and avoids a chain-ID mismatch error if your local Sui CLI is pointed at a devnet that has been wiped.
