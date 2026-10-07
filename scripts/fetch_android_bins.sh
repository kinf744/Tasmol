#!/bin/bash
# Stage official tunnel binaries as Android native libraries.
# ABI: armeabi-v7a (32-bit) UNIQUEMENT — l'arm64-v8a est retiré
# volontairement pour réduire la taille de l'APK (téléchargements
# facilités sur faibles connexions). Le bundle bin/arm64/ reste dans le
# dépôt si un jour la cible 64-bit devait revenir.
# The APK executes them from applicationInfo.nativeLibraryDir.
# Source: repository bundle bin/armv7/
#   (xray v26.9.8, zivpn/uz_core 1.4.9, hysteria v1.3.5, dnstt-client).
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

stage_abi() {
    local src_dir="$1" abi_dir="$2"
    local dir="$REPO_ROOT/android/app/src/main/jniLibs/$abi_dir"
    mkdir -p "$dir"
    local fail=0
    for pair in "xray lib_xray.so" "zivpn lib_zivpn.so" "slowdns lib_slowdns.so" "hysteria lib_hysteria.so" "utunnel lib_utunnel.so"; do
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

# Purge des résidus éventuels d'un ancien staging 64-bit (les .so d'un
# build local précédent seraient sinon embarqués dans l'APK).
rm -rf "$REPO_ROOT/android/app/src/main/jniLibs/arm64-v8a"

# geoip.dat/geosite.dat ne sont plus embarqués (≈30 Mo économisés) :
# l'app ne génère aucune règle geoip:/geosite: (vérif: aucune référence
# dans internal/ ni golib/). Un import JSON manuel avec règles geo
# échouera proprement au démarrage sans casser le reste.

if [ "$fail" -ne 0 ]; then
    echo "FAILED: some binaries are missing from bin/armv7/"
    exit 1
fi

echo "=== Staging complete ==="
file "$REPO_ROOT/android/app/src/main/jniLibs/armeabi-v7a"/*.so
