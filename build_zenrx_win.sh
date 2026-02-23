#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ZenRX Windows Cross-Compile Script (mingw-w64)
#
# Uses prebuilt static dependencies from zenrx_deps/windows/.
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install build-essential cmake mingw-w64
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZENRX_SRC="$SCRIPT_DIR/zenrx"
DEPS="$SCRIPT_DIR/zenrx_deps/windows"
BUILD_DIR="$SCRIPT_DIR/_build/windows"
JOBS="$(nproc 2>/dev/null || echo 4)"

note() { echo ">>> $*"; }

# ------------------------------------------------------------
# Prerequisite checks
# ------------------------------------------------------------
for cmd in x86_64-w64-mingw32-gcc-posix x86_64-w64-mingw32-g++-posix cmake make; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: missing $cmd. Install with: sudo apt install build-essential cmake mingw-w64"
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
note "Building ZenRX (Windows cross-compile)"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

cmake "$ZENRX_SRC" \
    -DCMAKE_TOOLCHAIN_FILE="$ZENRX_SRC/cmake/mingw-w64-x86_64.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_STATIC=ON \
    -DWITH_ICON=ON \
    -DCMAKE_C_FLAGS="-ffunction-sections -fdata-sections" \
    -DCMAKE_CXX_FLAGS="-ffunction-sections -fdata-sections" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++ -Wl,--gc-sections" \
    -DWITH_MSR=ON \
    -DHWLOC_INCLUDE_DIR="$DEPS/hwloc/include" \
    -DHWLOC_LIBRARY="$DEPS/hwloc/lib/libhwloc.a" \
    -DOPENSSL_INCLUDE_DIR="$DEPS/openssl/include" \
    -DOPENSSL_SSL_LIBRARY="$DEPS/openssl/lib64/libssl.a" \
    -DOPENSSL_CRYPTO_LIBRARY="$DEPS/openssl/lib64/libcrypto.a" \
    -DUV_INCLUDE_DIR="$DEPS/libuv/include" \
    -DUV_LIBRARY="$DEPS/libuv/lib/libuv.a"

make -j"$JOBS"

x86_64-w64-mingw32-strip zenrx.exe
mkdir -p "$SCRIPT_DIR/bin"
cp zenrx.exe "$SCRIPT_DIR/bin/zenrx.exe"

echo
echo "=================================================="
echo " ZenRX Windows build complete"
echo " Binary: $SCRIPT_DIR/bin/zenrx.exe"
echo "=================================================="
file "$SCRIPT_DIR/bin/zenrx.exe"
