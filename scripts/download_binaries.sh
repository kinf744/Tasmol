#!/bin/bash
# VPN App - official tunnel binaries for armv7 (armeabi-v7a)
#
# Sources (verified):
#   xray    : XTLS/Xray-core v26.5.9  -> Xray-linux-arm32-v7a.zip
#   zivpn   : zahidbd2/udp-zivpn udp-zivpn_1.4.9 -> udp-zivpn-linux-arm
#   slowdns : dnstt-client built from OutlineFoundation/dnstt (no upstream
#             armv7 release exists) - built by CI, stored in bin/armv7/
#   ssh     : Termux package (pkg install openssh)
#
# Priority: repository bundle (bin/armv7/) first, official URLs as fallback.
# The app resolves binaries via App.BinDir, so installing the repo bundle
# next to the vpn-app binary (or in $PREFIX/bin) is enough.

set -e

REPO_BIN_DIR="$(cd "$(dirname "$0")/../bin/armv7" && pwd)"
BIN_DIR="${1:-/data/data/com.termux/files/usr/bin}"
TMP_DIR="/tmp/vpn-binaries"
mkdir -p "$TMP_DIR" "$BIN_DIR"

echo "=== VPN App tunnel binaries (armv7) ==="
echo "Repo bundle : $REPO_BIN_DIR"
echo "Install dir : $BIN_DIR"

install_from_repo() {
    local name="$1"
    if [ -f "$REPO_BIN_DIR/$name" ]; then
        cp "$REPO_BIN_DIR/$name" "$BIN_DIR/$name"
        chmod +x "$BIN_DIR/$name"
        echo "  [repo] $name -> $BIN_DIR/$name"
        return 0
    fi
    return 1
}

# 1. SSH - Termux package manager
echo "[1/4] SSH client (Termux package)..."
if command -v pkg >/dev/null 2>&1; then
    pkg update -y && pkg install -y openssh
else
    echo "  pkg not found, skipping (ssh must be on PATH)"
fi

# 2. Xray v26.5.9
echo "[2/4] Xray v26.5.9..."
if ! install_from_repo xray; then
    cd "$TMP_DIR"
    wget -q "https://github.com/XTLS/Xray-core/releases/download/v26.5.9/Xray-linux-arm32-v7a.zip" -O xray.zip
    unzip -o xray.zip xray geoip.dat geosite.dat
    chmod +x xray
    cp xray "$BIN_DIR/xray"
    [ -f geoip.dat ] && cp geoip.dat geosite.dat "$BIN_DIR/" 2>/dev/null || true
    echo "  [url] xray -> $BIN_DIR/xray"
fi
# Routing data files (geoip/geosite) for Xray rules
for dat in geoip.dat geosite.dat; do
    if [ -f "$REPO_BIN_DIR/$dat" ] && [ ! -f "$BIN_DIR/$dat" ]; then
        cp "$REPO_BIN_DIR/$dat" "$BIN_DIR/$dat"
        echo "  [repo] $dat -> $BIN_DIR/$dat"
    fi
done

# 3. Zivpn (official udp-zivpn 1.4.9, ARM 32-bit, client+server binary)
echo "[3/4] Zivpn udp-zivpn_1.4.9 (linux-arm)..."
if ! install_from_repo zivpn; then
    cd "$TMP_DIR"
    wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm" -O zivpn
    chmod +x zivpn
    cp zivpn "$BIN_DIR/zivpn"
    echo "  [url] zivpn -> $BIN_DIR/zivpn"
fi

# 4. SlowDNS (dnstt-client, armv7)
echo "[4/4] SlowDNS (dnstt-client)..."
if ! install_from_repo slowdns; then
    echo "  No prebuilt armv7 slowdns in repo."
    echo "  It is built by CI from OutlineFoundation/dnstt into bin/armv7/slowdns."
    if command -v go >/dev/null 2>&1; then
        echo "  Go found - building dnstt-client for armv7..."
        cd "$TMP_DIR"
        rm -rf dnstt && git clone --depth 1 https://github.com/OutlineFoundation/dnstt.git
        cd dnstt
        GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BIN_DIR/slowdns" ./dnstt-client
        chmod +x "$BIN_DIR/slowdns"
        echo "  [src] slowdns -> $BIN_DIR/slowdns"
    else
        echo "  ERROR: install Go (pkg install golang) or use the repo bundle."
        exit 1
    fi
fi

# Verification
echo ""
echo "=== Verification ==="
file "$BIN_DIR/xray" "$BIN_DIR/zivpn" "$BIN_DIR/slowdns" 2>/dev/null || true
command -v ssh && ssh -V 2>&1 | head -1 || echo "ssh: MISSING from PATH"
"$BIN_DIR/xray" version 2>&1 | head -2 || true
echo ""
echo "=== Done. Binaries in $BIN_DIR ==="
echo "Point App.BinDir to this directory (or $HOME/bin) in config.yaml."
