#!/bin/bash
# Build the gomobile data-plane library (vpnlib.aar) for Android armv7.
#
# Requirements: Go >= 1.23, Android SDK + NDK, Java 17.
#   export ANDROID_HOME=/path/to/Android/Sdk
#   export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
#
# Output: android/app/libs/vpnlib.aar
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

GOMOBILE_VERSION="${GOMOBILE_VERSION:-v0.0.0-20240520174638-fa72addaaa1b}"

if [ -z "$ANDROID_HOME" ]; then
    echo "ERROR: ANDROID_HOME is not set"
    exit 1
fi

echo "=== Installing gomobile ($GOMOBILE_VERSION) ==="
go install "golang.org/x/mobile/cmd/gomobile@$GOMOBILE_VERSION"
go install "golang.org/x/mobile/cmd/gobind@$GOMOBILE_VERSION"
export PATH="$PATH:$(go env GOPATH)/bin"

echo "=== gomobile init (NDK: ${ANDROID_NDK_HOME:-default}) ==="
gomobile init

echo "=== Resolving gomobile bind dependency ==="
go get "golang.org/x/mobile@$GOMOBILE_VERSION"
go mod tidy

echo "=== Binding golib/vpnlib for android/arm (armeabi-v7a) ==="
mkdir -p android/app/libs
export GOARM=7
gomobile bind \
    -target=android/arm \
    -androidapi 24 \
    -ldflags='-s -w' \
    -o android/app/libs/vpnlib.aar \
    ./golib/vpnlib

echo ""
echo "=== Done ==="
ls -lh android/app/libs/vpnlib.aar
unzip -l android/app/libs/vpnlib.aar | head -20
