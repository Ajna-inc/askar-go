#!/bin/bash

set -e

ASKAR_VERSION="v0.4.1"
BASE_URL="https://github.com/openwallet-foundation/askar/releases/download"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture names
case "$ARCH" in
    x86_64)
        ARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Map OS names and handle special cases
case "$OS" in
    darwin)
        PLATFORM="darwin"
        # macOS has universal binaries
        ARCH="universal"
        LIB_NAME="libaries_askar.dylib"
        ;;
    linux)
        PLATFORM="linux"
        LIB_NAME="libaries_askar.so"
        ;;
    mingw*|msys*|cygwin*|windows*)
        PLATFORM="windows"
        LIB_NAME="aries_askar.dll"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Construct download URL
PACKAGE_NAME="library-${PLATFORM}-${ARCH}.tar.gz"
DOWNLOAD_URL="${BASE_URL}/${ASKAR_VERSION}/${PACKAGE_NAME}"

# Create native directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
NATIVE_DIR="${SCRIPT_DIR}/../native"
mkdir -p "${NATIVE_DIR}"

# Check if library already exists
if [ -f "${NATIVE_DIR}/${LIB_NAME}" ]; then
    echo "Askar library already installed at ${NATIVE_DIR}/${LIB_NAME}"
    exit 0
fi

# Download and extract
echo "Downloading Askar ${ASKAR_VERSION} for ${PLATFORM}-${ARCH}..."
echo "URL: ${DOWNLOAD_URL}"

TEMP_FILE="${NATIVE_DIR}/askar-temp.tar.gz"

# Download with curl or wget
if command -v curl > /dev/null 2>&1; then
    curl -L -o "${TEMP_FILE}" "${DOWNLOAD_URL}"
elif command -v wget > /dev/null 2>&1; then
    wget -O "${TEMP_FILE}" "${DOWNLOAD_URL}"
else
    echo "Error: Neither curl nor wget is available"
    exit 1
fi

# Extract
echo "Extracting..."
tar -xzf "${TEMP_FILE}" -C "${NATIVE_DIR}"

# Clean up
rm "${TEMP_FILE}"

# Verify installation
if [ -f "${NATIVE_DIR}/${LIB_NAME}" ]; then
    echo "Successfully installed Askar library to ${NATIVE_DIR}/${LIB_NAME}"
else
    echo "Error: Library file not found after extraction"
    exit 1
fi