# List all the available commands
default:
  just --list

# Fix Rust formatting
fmt:
  cargo fmt --all

# Fix TOML formatting with `taplo`
toml-fmt:
  taplo format

# Check Rust formatting
check-fmt:
  cargo fmt --all --check

# Rust `clippy` lints
clippy:
  cargo clippy --workspace --examples --tests --benches --all-features --all-targets --locked

# Compile each package independently with and without default features
check-packages:
  #!/bin/sh
  set -eu
  for package in alpen-wallet-keys alpen-wallet-keystore alpen-bitcoin-wallet alpen-wallet alpen-cli; do
    cargo check --locked -p "$package"
    cargo check --locked -p "$package" --no-default-features
  done

# Build documentation for the library APIs
# ssz-gen generic const expressions need the coherence solver on this nightly.
docs:
  RUSTDOCFLAGS="-A rustdoc::private-doc-tests -D warnings -Znext-solver=coherence" cargo doc --workspace --no-deps --locked

# TOML lint with `taplo`
toml-lint:
  taplo lint

# Check TOML formatting with `taplo`
toml-check-fmt:
  taplo format --check

# Rust unit tests with `cargo-nextest`
unit-test:
  cargo --locked nextest run --all-features --workspace

# Rust documentation tests
doctest:
  cargo test --doc --all-features --workspace

# Run all lints and formatting checks
lints: toml-check-fmt toml-lint check-fmt clippy check-packages

# Rust all tests
test: unit-test doctest

# Run all code-quality checks
precommit: test lints

# Publish crate to crates.io
publish:
  cargo publish --token $CARGO_REGISTRY_TOKEN

# Check supply chain security analsis with `cargo-audit`
audit:
  cargo audit

# Check GitHub Actions security analysis with `zizmor`
check-github-actions-security:
  zizmor .

# Performs one-time repo setup
setup:
  git config core.hooksPath .githooks
