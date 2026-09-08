# Move packages

This directory contains the Contra Move package. See the [top-level README](../README.md) for what it does.

## Authority flow

Contra supports an optional authority approval for protected operations. The issuer uses
`contra::enable_authority`, authenticated by `ManagementCap<T>`, to enable either the canonical
`Nitro` authority or a `Custom { id }` authority. The issuer uses `contra::disable_authority`, also
authenticated by `ManagementCap<T>`, to replace the active authority with `AuthorityKind::None`.

For the canonical Nitro authority:

1. The issuer creates the token's singleton `NitroAuthority<T>` with `nitro_authority::new` and
   shares it. The issuer and designated operator configure it through the `nitro_authority` module.
2. The client calls `nitro_authority::new_approval`, which verifies the submitted signature against
   a registered key and invokes package-private `contra::mint_nitro_authority_approval`.
3. The client passes the resulting `Option<Approval<T>>` to `contra::batched_transfer` or
   `contra::unwrap`. Contra requires it while the authority is enabled, reconstructs the operation
   binding, and validates and consumes the approval against that binding.

A custom authority creates and privately stores an `AuthorityCap<T>` bound to its object ID. The
issuer enables `Custom { id }`; after performing its own checks, the authority calls
`contra::mint_custom_authority_approval` to mint an approval.

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
