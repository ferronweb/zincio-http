#!/usr/bin/env bash
# Harvest a real-world QPACK fixture corpus into tests/fixtures/qpack/stories/.
#
# Sources (pinned):
#   - nghttp3 qpack example tool (independent encoder/decoder)
#   - ls-qpack test/qifs/*.qif (real-world header lists: facebook, netbsd)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/target/qpack-harvest"
OUT="$ROOT/tests/fixtures/qpack/stories"
NGHTTP3_COMMIT="e06a63ac6a0267149b480cd7fe04c8ea9a366d9e"
LSQPACK_COMMIT="91567706c41c0d97ab8dc576873ecd472d7869fa"

mkdir -p "$WORK" "$OUT/nghttp3"

clone_pinned() {
  local url="$1" dir="$2" commit="$3"
  if [ ! -d "$dir/.git" ]; then
    git clone --quiet "$url" "$dir"
  fi
  git -C "$dir" fetch --quiet origin "$commit"
  git -C "$dir" checkout --quiet --detach "$commit"
}

clone_pinned https://github.com/ngtcp2/nghttp3 "$WORK/nghttp3" "$NGHTTP3_COMMIT"
clone_pinned https://github.com/litespeedtech/ls-qpack "$WORK/ls-qpack" "$LSQPACK_COMMIT"

QPACK_BIN="$WORK/nghttp3/build/examples/qpack"
if [ ! -x "$QPACK_BIN" ]; then
  git -C "$WORK/nghttp3" submodule update --init lib/sfparse tests/munit >/dev/null
  cmake -S "$WORK/nghttp3" -B "$WORK/nghttp3/build" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF >/dev/null
  cmake --build "$WORK/nghttp3/build" --target qpack >/dev/null
fi

# Delegate to a helper script written in Python
python3 "$ROOT/scripts/harvest_qpack_fixtures.py" "$QPACK_BIN" "$WORK" "$OUT" "$NGHTTP3_COMMIT" "$LSQPACK_COMMIT"

echo "harvest complete -> $OUT/nghttp3"
