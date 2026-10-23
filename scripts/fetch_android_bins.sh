#!/bin/bash
# Stage official tunnel binaries as Android native libraries.
# ABIs: armeabi-v7a (32-bit) + arm64-v8a (64-bit) — compatibilité complète
# des deux architectures. Le bundle bin/arm64/ est commité dans le dépôt
# (mêmes versions que bin/armv7).
# The APK executes them from applicationInfo.nativeLibraryDir.
# Source: repository bundles bin/armv7/ and bin/arm64/
#   (xray v26.9.8, zivpn/uz_core 1.4.9, hysteria v1.3.5, dnstt-client).
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-android}"

stage_abi() {
    local src_dir="$1" abi_dir="$2"
    local dir="$REPO_ROOT/$TARGET_DIR/app/src/main/jniLibs/$abi_dir"
    mkdir -p "$dir"
    local fail=0
    TUNNELS="${TUNNELS:-xray zivpn slowdns hysteria utunnel}"
    pairs=""
    for t in $TUNNELS; do
        case "$t" in
            xray) pairs="$pairs xray:lib_xray.so" ;;
            zivpn) pairs="$pairs zivpn:lib_zivpn.so" ;;
            slowdns) pairs="$pairs slowdns:lib_slowdns.so" ;;
            hysteria) pairs="$pairs hysteria:lib_hysteria.so" ;;
            utunnel) pairs="$pairs utunnel:lib_utunnel.so" ;;
        esac
    done
    for pair in $pairs; do
        pair="${pair/:/ }"
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

# Dual-ABI : stage arm64-v8a depuis le bundle bin/arm64/ (mêmes binaires,
# même politique TUNNELS). Un bundle arm64 manquant n'est une erreur que
# si l'appelant exige les deux ABIs (REQUIRE_ARM64=1).
if [ -d "$REPO_ROOT/bin/arm64" ]; then
    if [ "${REQUIRE_ARM64:-0}" = "1" ]; then
        stage_abi "$REPO_ROOT/bin/arm64" "arm64-v8a" || fail=1
    else
        stage_abi "$REPO_ROOT/bin/arm64" "arm64-v8a" || true
    fi
else
    echo "  ⚠ bin/arm64 absent — APK 32-bit uniquement"
    if [ "${REQUIRE_ARM64:-0}" = "1" ]; then
        fail=1
    fi
fi

# geoip.dat/geosite.dat ne sont plus embarqués (≈30 Mo économisés) :
# l'app ne génère aucune règle geoip:/geosite: (vérif: aucune référence
# dans internal/ ni golib/). Un import JSON manuel avec règles geo
# échouera proprement au démarrage sans casser le reste.

if [ "$fail" -ne 0 ]; then
    echo "FAILED: some binaries are missing from bin/armv7/ or bin/arm64/"
    exit 1
fi

echo "=== Staging complete ==="
file "$REPO_ROOT/$TARGET_DIR/app/src/main/jniLibs/armeabi-v7a"/*.so
if [ -d "$REPO_ROOT/$TARGET_DIR/app/src/main/jniLibs/arm64-v8a" ]; then
    file "$REPO_ROOT/$TARGET_DIR/app/src/main/jniLibs/arm64-v8a"/*.so
fi
