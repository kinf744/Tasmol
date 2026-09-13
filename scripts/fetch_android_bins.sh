#!/bin/bash
# Stage official tunnel binaries as Android native libraries (armeabi-v7a).
# The APK executes them from applicationInfo.nativeLibraryDir.
# Source: repository bundle bin/armv7/ (xray v26.5.9, zivpn 1.4.9, slowdns).
# Xray runs as a child process fed by the TUN fd (fd 3 + XRAY_TUN_FD).
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$REPO_ROOT/bin/armv7"
JNILIBS_DIR="$REPO_ROOT/android/app/src/main/jniLibs/armeabi-v7a"

mkdir -p "$JNILIBS_DIR"

echo "=== Staging Android native binaries (armeabi-v7a) ==="

stage() {
    local src="$1" dst="$2"
    if [ ! -f "$SRC_DIR/$src" ]; then
        echo "  ✗ missing in repo bundle: $src (run CI job build-slowdns or download_binaries.sh)"
        return 1
    fi
    cp "$SRC_DIR/$src" "$JNILIBS_DIR/$dst"
    chmod +x "$JNILIBS_DIR/$dst"
    echo "  ✓ $src -> jniLibs/armeabi-v7a/$dst ($(stat -c%s "$JNILIBS_DIR/$dst") bytes)"
}

fail=0
stage xray lib_xray.so || fail=1
stage zivpn lib_zivpn.so || fail=1
stage slowdns lib_slowdns.so || fail=1

# Xray routing data next to the APK assets (copied to filesDir at runtime)
ASSETS_BIN="$REPO_ROOT/android/app/src/main/assets/bin"
mkdir -p "$ASSETS_BIN"
for dat in geoip.dat geosite.dat; do
    if [ -f "$SRC_DIR/$dat" ]; then
        cp "$SRC_DIR/$dat" "$ASSETS_BIN/$dat"
        echo "  ✓ $dat -> assets/bin/$dat"
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "FAILED: some binaries are missing from bin/armv7/"
    exit 1
fi

echo "=== Staging complete ==="
file "$JNILIBS_DIR"/*.so
