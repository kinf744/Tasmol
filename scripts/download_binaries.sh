#!/bin/bash
# Script to download VPN tunnel binaries for armv7 (armeabi-v7a) architecture
# Run this on your Android/Termux device

set -e

BIN_DIR="/data/data/com.termux/files/usr/bin"
TMP_DIR="/tmp/vpn-binaries"
mkdir -p "$TMP_DIR"
mkdir -p "$BIN_DIR"

echo "=== Downloading VPN binaries for armv7 ==="

# 1. SSH - Install via Termux package manager
echo "Installing SSH client..."
pkg update && pkg install -y openssh-tools openssh

# 2. SlowDNS client
echo "Downloading SlowDNS client for armv7..."
SLOWDNS_URL="https://github.com/xtls/xray-core/releases/download/v24.8.31/xray-linux-armv7-v3.zip"
cd "$TMP_DIR"
wget -q "$SLOWDNS_URL" -O xray.zip
unzip -o xray.zip xray
chmod +x xray
cp xray "$BIN_DIR/slowdns"
echo "SlowDNS installed to $BIN_DIR/slowdns"

# 3. Xray core (supports VMess, VLESS, Trojan, Shadowsocks, etc.)
echo "Downloading Xray core for armv7..."
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v24.8.31/Xray-linux-armv7-v3.zip"
wget -q "$XRAY_URL" -O xray-core.zip
unzip -o xray-core.zip xray
chmod +x xray
cp xray "$BIN_DIR/xray"
echo "Xray installed to $BIN_DIR/xray"

# 4. Zivpn
echo "Downloading Zivpn for armv7..."
ZIVPN_URL="https://github.com/zaidka/zivpn/releases/download/v0.1.2/zivpn_0.1.2_linux_armv7.tar.gz"
wget -q "$ZIVPN_URL" -O zivpn.tar.gz
tar -xzf zivpn.tar.gz zivpn
chmod +x zivpn
cp zivpn "$BIN_DIR/zivpn"
echo "Zivpn installed to $BIN_DIR/zivpn"

# 5. UDPGW (UDP Gateway) for UDP tunneling
echo "Downloading UDPGW for armv7..."
UDPGW_URL="https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz"
wget -q "$UDPGW_URL" -O badvpn.tar.gz
tar -xzf badvpn.tar.gz
cd badvpn-1.999.130
cmake -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 .
make -j$(nproc)
cp udpgw/badvpn-udpgw "$BIN_DIR/udpgw"
cd "$TMP_DIR"
chmod +x "$BIN_DIR/udpgw"
echo "UDPGW installed to $BIN_DIR/udpgw"

# 6. Additional tools
echo "Installing additional tools..."
pkg install -y iproute2 wireguard-tools dnsutils net-tools curl wget jq cmake make gcc

# Verify installations
echo ""
echo "=== Verification ==="
which ssh && ssh -V
which slowdns && slowdns -version 2>&1 | head -1
which xray && xray version 2>&1 | head -1
which zivpn && zivpn -version 2>&1 | head -1
which udpgw && udpgw --version 2>&1 | head -1

echo ""
echo "=== All binaries installed successfully! ==="
echo "Binaries location: $BIN_DIR"