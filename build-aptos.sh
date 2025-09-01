#!/bin/bash
set -e

# Copy Aptos-specific Cargo.toml
cp Cargo-aptos.toml Cargo.toml

# Remove Cargo.lock to avoid conflicts
rm -f Cargo.lock

# Build with Aptos features
cargo build --release --features aptos
