#!/usr/bin/env bash
# Feature-surface matrix for the explicitly opt-in test-support API.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    target="$CARGO_TARGET_DIR"
    created=0
else
    target="$(pwd)/.feature-surface-target"
    created=1
    export CARGO_TARGET_DIR="$target"
fi
cleanup() {
    if [ "$created" = 1 ]; then
        rm -rf "$target"
    fi
}
trap cleanup EXIT

if [ -z "${TMPDIR:-}" ]; then
    export TMPDIR="$target/tmp"
    mkdir -p "$TMPDIR"
fi

docs="$target/doc/neotales_ssh"
page="$docs/server/struct.ServerTransport.html"

cargo doc -p neotales-ssh --no-deps >/dev/null
if grep -q "write_rekey_ignorable" "$page"; then
    echo "test-support hook is present without the feature" >&2
    exit 1
fi

cargo doc -p neotales-ssh --features test-support --no-deps >/dev/null
if ! grep -q "write_rekey_ignorable" "$page"; then
    echo "test-support hook is missing with the feature" >&2
    exit 1
fi

cargo check -p neotales-ssh --features test-support >/dev/null
cargo test -p neotales-ssh --features test-support --test feature_surface >/dev/null
cargo test -p neotales-ssh --features test-support --test server_transport test_support_rekey_ignorable >/dev/null
echo "test-support surface matrix passed"
