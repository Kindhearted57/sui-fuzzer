#!/bin/bash
set -e

# Copy Sui-specific Cargo.toml
cp Cargo-sui.toml Cargo.toml

# Remove Cargo.lock to avoid conflicts
rm -f Cargo.lock

# Build with Sui features
cargo build --release --features sui