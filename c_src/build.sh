#!/bin/sh
# Build script for erlang-derp NIFs
# Uses CMake for cross-platform compatibility

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

# Detect cmake version
if command -v cmake3 >/dev/null 2>&1; then
    CMAKE=cmake3
else
    CMAKE=cmake
fi

# Handle clean command
if [ "$1" = "clean" ]; then
    rm -rf "${BUILD_DIR}"
    rm -f "${SCRIPT_DIR}/../priv/"*.so
    exit 0
fi

# Create build directory and configure
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure with CMake if not already done
if [ ! -f CMakeCache.txt ]; then
    ${CMAKE} ..
fi

# Build the NIFs
${CMAKE} --build . --target derp_sodium_nif --config Release
${CMAKE} --build . --target derp_tls_nif --config Release

echo "Build complete."
