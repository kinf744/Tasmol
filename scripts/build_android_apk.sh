#!/bin/bash
# Build Android APK for VPN App (requires Android SDK/NDK)

set -e

ANDROID_DIR="/root/vpn-app/android"
OUTPUT_DIR="/root/vpn-app/build/android"

echo "=== Building Android APK ==="
echo "Android project: $ANDROID_DIR"
echo "Output: $OUTPUT_DIR"

# Check for Android SDK
if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
    echo "ERROR: ANDROID_HOME or ANDROID_SDK_ROOT not set"
    echo "Please install Android SDK and set environment variable"
    exit 1
fi

SDK_PATH="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
echo "Using Android SDK: $SDK_PATH"

# Check for gradle wrapper
cd "$ANDROID_DIR"
if [ ! -f "gradlew" ]; then
    echo "Generating Gradle wrapper..."
    gradle wrapper --gradle-version 8.3
fi

chmod +x gradlew

# Build APK
echo "Building APK..."
./gradlew assembleRelease

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

# Copy APK to output
mkdir -p "$OUTPUT_DIR"
cp app/build/outputs/apk/release/app-release.apk "$OUTPUT_DIR/vpn-app-armv7.apk"

echo ""
echo "=== Build successful! ==="
echo "APK location: $OUTPUT_DIR/vpn-app-armv7.apk"
ls -lh "$OUTPUT_DIR/vpn-app-armv7.apk"

echo ""
echo "To install on device:"
echo "  adb install $OUTPUT_DIR/vpn-app-armv7.apk"
echo ""
echo "Note: This APK is a WebView wrapper that connects to the VPN App"
echo "running in Termux. You still need to install and run the Go binary"
echo "in Termux using the install_termux.sh script."