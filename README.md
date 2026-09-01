# Alpen CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![CI](https://github.com/alpenlabs/alpen-cli/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/alpen-cli/actions)

`alpen` is a command-line wallet for managing Bitcoin and Alpen funds and
interacting with the Strata bridge.

## Install official binaries

Official release archives for Linux (x86-64), macOS (Apple silicon), and
Windows (x86-64) are available from [GitHub Releases]. Each release includes a
`SHA256SUMS` file and build-provenance attestations. Verify the downloaded
archive against `SHA256SUMS` before running it.

[GitHub Releases]: https://github.com/alpenlabs/alpen-cli/releases

## Install from source

The repository pins its Rust toolchain in `rust-toolchain.toml`.

```sh
cargo install --locked --git https://github.com/alpenlabs/alpen-cli --bin alpen
```

To build the checked-out source instead:

```sh
cargo build --release --locked --bin alpen
```

## Configuration

Run the configuration command to locate or update the CLI configuration:

```sh
alpen config
```

The configuration selects the Bitcoin backend and network parameters used by
the wallet. Network parameters must match the deployed ASM and OL configuration.

List the available commands with:

```sh
alpen --help
```

## Security

This software manages wallet seed material and can authorize transactions.
Verify downloaded release artifacts before running them and protect the host on
which the CLI is used. Report vulnerabilities according to
[`SECURITY.md`](SECURITY.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

This project is dual-licensed under the MIT and Apache 2.0 licenses.
