#!/usr/bin/env bash
# Negative tests for the feature-surface matrix script. Everything runs in a
# unique temporary fixture; the checkout is never written to or deleted from.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
matrix="$script_dir/check-test-support-feature.sh"
bash -n "$matrix"
bash -n "$0"

fixture="$(mktemp -d "${TMPDIR:-/tmp}/neotales-ssh-feature-test.XXXXXX")"
cleanup() {
    rm -rf "$fixture"
}
trap cleanup EXIT

mkdir -p "$fixture/tools" "$fixture/bin" "$fixture/tmp"
cp "$matrix" "$fixture/tools/check-test-support-feature.sh"
chmod +x "$fixture/tools/check-test-support-feature.sh"

cat >"$fixture/bin/cargo" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
target="${CARGO_TARGET_DIR:?}"
page="$target/doc/neotales_ssh/server/struct.ServerTransport.html"
case "${1:-}" in
    doc)
        mkdir -p "$(dirname "$page")"
        if printf '%s\n' "$@" | grep -qx 'test-support'; then
            printf 'write_rekey_ignorable\n' >"$page"
        else
            printf 'no hook\n' >"$page"
        fi
        ;;
    check | test)
        ;;
    *)
        echo "unexpected fake cargo arguments: $*" >&2
        exit 1
        ;;
esac
FAKE
chmod +x "$fixture/bin/cargo"

# A pre-existing checkout-like path with a sentinel must survive.
mkdir -p "$fixture/.feature-surface-target"
printf 'keep\n' >"$fixture/.feature-surface-target/sentinel"
# A pre-existing name in the temp root must also survive the unique mktemp.
mkdir -p "$fixture/tmp/neotales-ssh-feature-surface"
printf 'keep\n' >"$fixture/tmp/neotales-ssh-feature-surface/target.PREEXISTING"

# Simulate an inherited external target directory. The default invocation must
# unset it so the fake cargo cannot overwrite real generated docs.
inherited="$fixture/inherited"
mkdir -p "$inherited/doc/neotales_ssh/server"
printf 'keep\n' >"$inherited/sentinel"
printf 'real-doc\n' >"$inherited/doc/neotales_ssh/server/struct.ServerTransport.html"
inherited_hash="$(sha256sum "$inherited/doc/neotales_ssh/server/struct.ServerTransport.html" | cut -d' ' -f1)"

export CARGO_TARGET_DIR="$inherited"
env -u CARGO_TARGET_DIR PATH="$fixture/bin:$PATH" TMPDIR="$fixture/tmp" \
    "$fixture/tools/check-test-support-feature.sh" >/dev/null

if [ ! -f "$fixture/.feature-surface-target/sentinel" ]; then
    echo "the matrix script removed a pre-existing checkout sentinel" >&2
    exit 1
fi
if [ ! -f "$fixture/tmp/neotales-ssh-feature-surface/target.PREEXISTING" ]; then
    echo "the matrix script removed a pre-existing temp-root name" >&2
    exit 1
fi
if find "$fixture/tmp/neotales-ssh-feature-surface" -maxdepth 1 \
    -name 'target.*' ! -name 'target.PREEXISTING' | grep -q .; then
    echo "the matrix script left its own mktemp target behind" >&2
    exit 1
fi
if [ ! -f "$inherited/sentinel" ]; then
    echo "the default invocation removed the inherited sentinel" >&2
    exit 1
fi
if [ "$(sha256sum "$inherited/doc/neotales_ssh/server/struct.ServerTransport.html" | cut -d' ' -f1)" != "$inherited_hash" ]; then
    echo "the default invocation overwrote inherited generated docs" >&2
    exit 1
fi

# An explicit CARGO_TARGET_DIR must be honored, must keep its docs, and must
# not touch the inherited directory.
explicit="$fixture/explicit"
CARGO_TARGET_DIR="$explicit" PATH="$fixture/bin:$PATH" TMPDIR="$fixture/tmp" \
    "$fixture/tools/check-test-support-feature.sh" >/dev/null
if [ ! -f "$explicit/doc/neotales_ssh/server/struct.ServerTransport.html" ]; then
    echo "the matrix script ignored an explicit CARGO_TARGET_DIR" >&2
    exit 1
fi
if [ ! -f "$fixture/.feature-surface-target/sentinel" ]; then
    echo "the matrix script removed a pre-existing checkout sentinel on the explicit run" >&2
    exit 1
fi
if [ "$(sha256sum "$inherited/doc/neotales_ssh/server/struct.ServerTransport.html" | cut -d' ' -f1)" != "$inherited_hash" ]; then
    echo "the explicit invocation overwrote inherited generated docs" >&2
    exit 1
fi

echo "feature-surface script checks passed"
