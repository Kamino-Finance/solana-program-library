#
# This file maintains the solana versions for use by CI.
#
# Obtain the environment variables without any automatic updating:
#   $ source ci/solana-version.sh
#
# Obtain the environment variables and install update:
#   $ source ci/solana-version.sh install

# Then to access the solana version:
#   $ echo "$solana_version"
#

if [[ -n $SOLANA_VERSION ]]; then
  solana_version="$SOLANA_VERSION"
else
  # v1.16.13 (this branch's original pin) is EOL and no longer hosted by any release server
  # (release.solana.com is decommissioned; release.anza.xyz only serves >=v1.17). Use the nearest
  # anza-hosted release for the CI toolchain — crate deps stay pinned at 1.16.x via Cargo.lock, so
  # only the build-sbf toolchain version moves.
  solana_version=v1.17.34
fi

export solana_version="$solana_version"
export PATH="$HOME"/.local/share/solana/install/active_release/bin:"$PATH"

if [[ -n $1 ]]; then
  case $1 in
  install)
    sh -c "$(curl -sSfL https://release.anza.xyz/$solana_version/install)"
    solana --version
    ;;
  *)
    echo "solana-version.sh: Note: ignoring unknown argument: $1" >&2
    ;;
  esac
fi
