#!/bin/bash
# Cross-compile VPN App for Android/Termux (armv7/armeabi-v7a)

set -e

VERSION="${1:-1.0.0}"
COMMIT="${2:-$(git rev-parse --short HEAD 2>/dev/null || echo 'dev')}"
DATE="${3:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

OUTPUT_DIR="/root/vpn-app/build/armv7"
BINARY_NAME="vpn-app"

mkdir -p "$OUTPUT_DIR"

echo "=== Building VPN App for armv7 (armeabi-v7a) ==="
echo "Version: $VERSION"
echo "Commit: $COMMIT"
echo "Date: $DATE"
echo "Output: $OUTPUT_DIR/$BINARY_NAME"

# Set Go environment for cross-compilation
export GOOS=linux
export GOARCH=arm
export GOARM=7
export CGO_ENABLED=1

# Use Termux-compatible toolchain
# For CGO, we need arm-linux-androideabi toolchain
export CC=arm-linux-androideabi-gcc
export CXX=arm-linux-androideabi-g++
export AR=arm-linux-androideabi-ar
export STRIP=arm-linux-androideabi-strip

# Alternative: Use Go's pure Go implementation where possible
# Set CGO_CFLAGS for Android
export CGO_CFLAGS="-I/data/data/com.termux/files/usr/include"
export CGO_LDFLAGS="-L/data/data/com.termux/files/usr/lib"

cd /root/vpn-app

# Download dependencies
echo "Downloading dependencies..."
go mod download
go mod verify

# Build with version info
LDFLAGS="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.date=$DATE"

echo "Compiling..."
go build -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/$BINARY_NAME" ./cmd/vpn-app

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Strip binary to reduce size
if command -v arm-linux-androideabi-strip &> /dev/null; then
    arm-linux-androideabi-strip "$OUTPUT_DIR/$BINARY_NAME"
elif command -v strip &> /dev/null; then
    strip "$OUTPUT_DIR/$BINARY_NAME"
fi

# Verify binary
echo ""
echo "=== Build successful! ==="
file "$OUTPUT_DIR/$BINARY_NAME"
ls -lh "$OUTPUT_DIR/$BINARY_NAME"

echo ""
echo "Binary location: $OUTPUT_DIR/$BINARY_NAME"
echo ""
echo "To install on Android/Termux:"
echo "  1. Copy binary to device: adb push $OUTPUT_DIR/$BINARY_NAME /sdcard/"
echo "  2. In Termux: cp /sdcard/$BINARY_NAME \$PREFIX/bin/"
echo "  3. chmod +x \$PREFIX/bin/$BINARY_NAME"
echo "  4. Run: $BINARY_NAME"