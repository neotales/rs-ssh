#!/usr/bin/env bash
# Checks that the feature-surface matrix uses a unique target and honors an
# explicit CARGO_TARGET_DIR without deleting a pre-existing path.
set -euo pipefail
cd "$(dirname "$0")/.."

sentinel_dir=".feature-surface-target"
sentinel="$sentinel_dir/sentinel"
mkdir -p "$sentinel_dir"
printf 'keep\n' >"$sentinel"

./tools/check-test-support-feature.sh >/dev/null
if [ ! -f "$sentinel" ]; then
    echo "the feature-surface script removed a pre-existing sentinel" >&2
    exit 1
fi
rm -rf "$sentinel_dir"

explicit="$(mktemp -d "${TMPDIR:-/tmp}/neotales-ssh-explicit.XXXXXX")"
trap 'rm -rf "$explicit"' EXIT
CARGO_TARGET_DIR="$explicit" ./tools/check-test-support-feature.sh >/dev/null
if [ ! -d "$explicit/doc/neotales_ssh" ]; then
    echo "the feature-surface script ignored CARGO_TARGET_DIR" >&2
    exit 1
fi
if [ -e "$sentinel_dir" ]; then
    echo "the feature-surface script created a fixed target path" >&2
    exit 1
fi
echo "feature-surface script checks passed"
