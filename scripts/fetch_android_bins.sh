#!/bin/bash
# Stage official tunnel binaries as Android native libraries.
# ABIs: armeabi-v7a (32-bit) + arm64-v8a (64-bit).
# The APK executes them from applicationInfo.nativeLibraryDir.
# Sources: repository bundles bin/armv7/ et bin/arm64/
#   (xray v26.9.8, zivpn/uz_core 1.4.9, hysteria v1.3.5, dnstt-client).
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

stage_abi() {
    local src_dir="$1" abi_dir="$2"
    local dir="$REPO_ROOT/android/app/src/main/jniLibs/$abi_dir"
    mkdir -p "$dir"
    local fail=0
    for pair in "xray lib_xray.so" "zivpn lib_zivpn.so" "slowdns lib_slowdns.so" "hysteria lib_hysteria.so"; do
        local src="${pair%% *}" dst="${pair##* }"
        if [ ! -f "$src_dir/$src" ]; then
            echo "  ✗ missing in repo bundle: $src_dir/$src"
            fail=1
            continue
        fi
        cp "$src_dir/$src" "$dir/$dst"
        chmod +x "$dir/$dst"
        echo "  ✓ $src -> jniLibs/$abi_dir/$dst ($(stat -c%s "$dir/$dst") bytes)"
    done
    return $fail
}

echo "=== Staging Android native binaries ==="

fail=0
stage_abi "$REPO_ROOT/bin/armv7" "armeabi-v7a" || fail=1
stage_abi "$REPO_ROOT/bin/arm64" "arm64-v8a" || fail=1

# geoip.dat/geosite.dat ne sont plus embarqués (≈30 Mo économisés) :
# l'app ne génère aucune règle geoip:/geosite: (vérif: aucune référence
# dans internal/ ni golib/). Un import JSON manuel avec règles geo
# échouera proprement au démarrage sans casser le reste.

if [ "$fail" -ne 0 ]; then
    echo "FAILED: some binaries are missing from bin/armv7/ or bin/arm64/"
    exit 1
fi

echo "=== Staging complete ==="
file "$REPO_ROOT/android/app/src/main/jniLibs/armeabi-v7a"/*.so
file "$REPO_ROOT/android/app/src/main/jniLibs/arm64-v8a"/*.so
