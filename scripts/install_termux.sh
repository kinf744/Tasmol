#!/bin/bash
# VPN App - Termux Installation Script for Android (armv7/armeabi-v7a)
# Run this script INSIDE Termux on your Android device

set -e

echo "=========================================="
echo "  VPN App - Termux Installer (armv7)"
echo "=========================================="
echo ""

# Check architecture
ARCH=$(uname -m)
echo "Device architecture: $ARCH"
if [[ "$ARCH" != "armv7"* ]] && [[ "$ARCH" != "arm"* ]]; then
    echo "WARNING: This script is for armv7/armeabi-v7a architecture"
    echo "Your device reports: $ARCH"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update packages
echo ""
echo "[1/7] Updating Termux packages..."
pkg update -y && pkg upgrade -y

# Install dependencies
echo ""
echo "[2/7] Installing dependencies..."
pkg install -y \
    git \
    curl \
    wget \
    unzip \
    tar \
    gzip \
    iproute2 \
    wireguard-tools \
    dnsutils \
    net-tools \
    openssh \
    openssl-tool \
    jq \
    tsu \
    procps \
    util-linux \
    coreutils \
    binutils \
    clang \
    make \
    cmake \
    go \
    rust \
    cargo

# Create directories
echo ""
echo "[3/7] Creating directories..."
mkdir -p ~/.vpn-app
mkdir -p ~/bin
mkdir -p ~/vpn-binaries

# Download tunnel binaries
echo ""
echo "[4/7] Downloading tunnel binaries for armv7..."

cd ~/vpn-binaries

# Xray (supports VMess, VLESS, Trojan, Shadowsocks, etc.)
echo "  Downloading Xray..."
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v24.8.31/Xray-linux-armv7-v3.zip"
wget -q "$XRAY_URL" -O xray.zip
unzip -o xray.zip xray
chmod +x xray
cp xray ~/bin/xray

# SlowDNS
echo "  Downloading SlowDNS..."
SLOWDNS_URL="https://github.com/xtls/xray-core/releases/download/v24.8.31/xray-linux-armv7-v3.zip"
# SlowDNS is included in xray binary as 'xray' with 'dns' protocol
# But we can also get standalone slowdns
# For now, use xray for DNS over HTTPS/TLS
ln -sf ~/bin/xray ~/bin/slowdns

# Zivpn
echo "  Downloading Zivpn..."
ZIVPN_URL="https://github.com/zaidka/zivpn/releases/download/v0.1.2/zivpn_0.1.2_linux_armv7.tar.gz"
wget -q "$ZIVPN_URL" -O zivpn.tar.gz
tar -xzf zivpn.tar.gz zivpn
chmod +x zivpn
cp zivpn ~/bin/zivpn

# UDPGW (badvpn)
echo "  Building UDPGW..."
UDPGW_URL="https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz"
wget -q "$UDPGW_URL" -O badvpn.tar.gz
tar -xzf badvpn.tar.gz
cd badvpn-1.999.130
cmake -DCMAKE_INSTALL_PREFIX=/data/data/com.termux/files/usr -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 .
make -j$(nproc)
cp udpgw/badvpn-udpgw ~/bin/udpgw
cd ~/vpn-binaries

# Verify binaries
echo ""
echo "[5/7] Verifying binaries..."
for bin in xray zivpn udpgw; do
    if [ -f ~/bin/$bin ]; then
        echo "  ✓ $bin: $(~/bin/$bin --version 2>&1 | head -1 || echo 'installed')"
    else
        echo "  ✗ $bin: MISSING"
    fi
done

# Download VPN App binary
echo ""
echo "[6/7] Downloading VPN App binary..."
VPN_APP_URL="https://github.com/your-repo/vpn-app/releases/latest/download/vpn-app-armv7"
# For now, we'll build from source if Go is available
if command -v go &> /dev/null; then
    echo "  Building from source..."
    cd ~
    git clone https://github.com/your-repo/vpn-app.git 2>/dev/null || echo "Repo already exists"
    cd vpn-app
    GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=1 go build -ldflags="-s -w" -o ~/bin/vpn-app ./cmd/vpn-app
    chmod +x ~/bin/vpn-app
else
    echo "  Go not available, please download pre-built binary"
    echo "  Download from: https://github.com/your-repo/vpn-app/releases"
fi

# Create config
echo ""
echo "[7/7] Creating default configuration..."
cat > ~/.vpn-app/config.yaml << 'EOF'
app:
  name: "VPN App"
  version: "1.0.0"
  web_port: 8080
  web_host: "0.0.0.0"
  log_level: "info"
  data_dir: "/data/data/com.termux/files/home/.vpn-app"
  bin_dir: "/data/data/com.termux/files/usr/bin"

tunnels: []

network:
  interface: "tun0"
  mtu: 1500
  dns:
    - "1.1.1.1"
    - "8.8.8.8"
  exclude_ips:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"

features:
  kill_switch: true
  split_tunneling: false
  dns_leak_protection: true
  auto_reconnect: true
  reconnect_interval: 5
  max_retries: 3
  obfuscation: false

udpgw:
  enabled: true
  listen_addr: "127.0.0.1:7300"
  max_clients: 100
  timeout: 30
  mtu: 1500
  log_level: "info"
EOF

# Create startup script
cat > ~/bin/vpn-start << 'EOF'
#!/bin/bash
# VPN App startup script for Termux

# Request wake lock to prevent CPU sleep
termux-wake-lock

# Enable IP forwarding
su -c "echo 1 > /proc/sys/net/ipv4/ip_forward" 2>/dev/null || echo "Root needed for IP forwarding"

# Start VPN App
cd ~/.vpn-app
exec vpn-app -config ~/.vpn-app/config.yaml
EOF
chmod +x ~/bin/vpn-start

# Create systemd-like service for Termux:Boot
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/vpn-app << 'EOF'
#!/bin/bash
# Auto-start VPN App on boot (requires Termux:Boot app)
sleep 10
/data/data/com.termux/files/home/bin/vpn-start >> /data/data/com.termux/files/home/.vpn-app/boot.log 2>&1 &
EOF
chmod +x ~/.termux/boot/vpn-app

# Create aliases
cat >> ~/.bashrc << 'EOF'

# VPN App aliases
alias vpn='vpn-app'
alias vpn-start='~/bin/vpn-start'
alias vpn-stop='pkill -f vpn-app'
alias vpn-status='curl -s http://localhost:8080/api/v1/status | jq'
alias vpn-logs='tail -f ~/.vpn-app/vpn.log'
alias vpn-config='nano ~/.vpn-app/config.yaml'
EOF

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Installed binaries in ~/bin/:"
ls -la ~/bin/
echo ""
echo "Configuration: ~/.vpn-app/config.yaml"
echo ""
echo "To start VPN App:"
echo "  vpn-start"
echo ""
echo "Or run directly:"
echo "  vpn-app -config ~/.vpn-app/config.yaml"
echo ""
echo "Web UI will be available at:"
echo "  http://localhost:8080"
echo "  http://<your-phone-ip>:8080"
echo ""
echo "For auto-start on boot:"
echo "  1. Install 'Termux:Boot' from F-Droid"
echo "  2. Enable 'Allow execution' in Termux:Boot settings"
echo ""
echo "Required Termux permissions:"
echo "  - termux-wake-lock (prevent sleep)"
echo "  - Root access (for IP forwarding, TUN device)"
echo ""
echo "To grant root access to Termux:"
echo "  su"
echo "  # Allow in Magisk/SuperSU prompt"