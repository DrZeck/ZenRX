#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ZenRX Linux Build Script
#
# Uses prebuilt static dependencies from zenrx_deps/linux/.
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install build-essential cmake
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZENRX_SRC="$SCRIPT_DIR/zenrx"
DEPS="$SCRIPT_DIR/zenrx_deps/linux"
BUILD_DIR="$SCRIPT_DIR/_build/linux"
JOBS="$(nproc 2>/dev/null || echo 4)"

note() { echo ">>> $*"; }

# ------------------------------------------------------------
# Prerequisite checks
# ------------------------------------------------------------
for cmd in gcc g++ cmake make; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: missing $cmd. Install with: sudo apt install build-essential cmake"
        exit 1
    }
done

for lib in "$DEPS/hwloc/lib/libhwloc.a" \
           "$DEPS/openssl/lib64/libssl.a" \
           "$DEPS/openssl/lib64/libcrypto.a" \
           "$DEPS/libuv/lib/libuv.a"; do
    [ -f "$lib" ] || { echo "ERROR: missing $lib"; exit 1; }
done

# ------------------------------------------------------------
# Build
# ------------------------------------------------------------
note "Building ZenRX (Linux)"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

cmake "$ZENRX_SRC" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_STATIC=ON \
    -DCMAKE_C_FLAGS="-ffunction-sections -fdata-sections" \
    -DCMAKE_CXX_FLAGS="-ffunction-sections -fdata-sections" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--gc-sections" \
    -DWITH_MSR=ON \
    -DHWLOC_INCLUDE_DIR="$DEPS/hwloc/include" \
    -DHWLOC_LIBRARY="$DEPS/hwloc/lib/libhwloc.a" \
    -DOPENSSL_INCLUDE_DIR="$DEPS/openssl/include" \
    -DOPENSSL_SSL_LIBRARY="$DEPS/openssl/lib64/libssl.a" \
    -DOPENSSL_CRYPTO_LIBRARY="$DEPS/openssl/lib64/libcrypto.a" \
    -DUV_INCLUDE_DIR="$DEPS/libuv/include" \
    -DUV_LIBRARY="$DEPS/libuv/lib/libuv.a"

make -j"$JOBS"

strip zenrx
mkdir -p "$SCRIPT_DIR/bin"
cp zenrx "$SCRIPT_DIR/bin/zenrx"

echo
echo "=================================================="
echo " ZenRX Linux build complete"
echo " Binary: $SCRIPT_DIR/bin/zenrx"
echo "=================================================="
file "$SCRIPT_DIR/bin/zenrx"
