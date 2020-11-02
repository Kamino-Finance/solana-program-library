#!/usr/bin/env bash

set -e

export RUSTFLAGS="-D warnings"
export RUSTBACKTRACE=1

# For all BPF programs
for Xargo_toml in $(git ls-files -- '*/Xargo.toml'); do
  program_dir=$(dirname "$Xargo_toml")

  if [ "$program_dir" == "token-swap/program" ]; then	
    address="SwaPpA9LAaLfeLi3a68M4DjnLqgtticKg6CnyNwgAC8"	
    SWAP_PROGRAM_OWNER_FEE_ADDRESS="$address" cargo build-bpf --manifest-path=token-swap/program/Cargo.toml --dump --features production	
    mv spl_token_swap.so spl_token_swap_production.so	
  fi	

  cargo build-bpf --manifest-path="$program_dir"/Cargo.toml --dump
done


cargo build
cargo test -- --nocapture
cargo run --manifest-path=utils/test-client/Cargo.toml
cargo test --manifest-path=themis/client_ristretto/Cargo.toml -- --nocapture

#  # Check generated C headers
#  cargo run --manifest-path=utils/cgen/Cargo.toml
#
#  git diff --exit-code token/program/inc/token.h
#  cc token/program/inc/token.h -o target/token.gch
#  git diff --exit-code token-swap/program/inc/token-swap.h
#  cc token-swap/program/inc/token-swap.h -o target/token-swap.gch

exit 0
