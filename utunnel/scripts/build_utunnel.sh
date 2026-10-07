#!/usr/bin/env bash
# ── build_utunnel.sh — binaires serveur/client, cross-compile ──────────
#
#   amd64   : serveurs (VPS Linux)
#   arm64   : box/ARM récents
#   armv7   : Android/Termux/ARMv7 (comme le reste de l'écosystème Tasmol)
#
#   garble (-literals -tiny -seed=random) quand disponible : mêmes
#   protections anti-analyse statique que build-armv7.yml.
# ───────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-bin-utunnel}"
mkdir -p "$OUT"

# garble si présent dans le PATH (go install mvdan.cc/garble@v0.13.0)
if command -v garble &>/dev/null; then
    BUILD="garble -literals -tiny -seed=random build"
else
    echo "[i] garble absent — build standard (installez-le pour l'obfuscation)"
    BUILD="go build"
fi

build_one() { # $1 GOOS $2 GOARCH $3 GOARM $4 suffix
    local env_arch=()
    export GOOS="$1" GOARCH="$2"
    export CGO_ENABLED=0
    [[ -n "${3:-}" ]] && export GOARM="$3" || unset GOARM 2>/dev/null || true
    local ld="-s -w -X main.version=$(date -u +%Y%m%d) -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo n/a)"
    $BUILD -trimpath -ldflags="$ld" -o "$OUT/utunnel-server-$4" ./cmd/utunnel-server
    $BUILD -trimpath -ldflags="$ld" -o "$OUT/utunnel-client-$4" ./cmd/utunnel-client
    echo "[✓] $4 : $(ls -lh "$OUT" | grep "$4" | awk '{print $5}')"
}

build_one linux amd64 "" amd64
build_one linux arm64 "" arm64
build_one linux arm 7   armv7

echo "Binaires dans $OUT/"
