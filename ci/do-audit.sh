#!/usr/bin/env bash

set -e
cd "$(dirname "$0")/.."
source ./ci/rust-version.sh stable

cargo_audit_ignores=(
  # ed25519-dalek: Double Public Key Signing Function Oracle Attack
  #
  # Remove once SPL upgrades to ed25519-dalek v2
  --ignore RUSTSEC-2022-0093

  # curve25519-dalek
  #
  # Remove once SPL upgrades to curve25519-dalek v4
  --ignore RUSTSEC-2024-0344
)
cargo +"$rust_stable" audit "${cargo_audit_ignores[@]}"
