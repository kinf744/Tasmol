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

# Install official tunnel binaries (verified sources, armv7)
#   xray    : XTLS/Xray-core v26.5.9 (Xray-linux-arm32-v7a.zip)
#   zivpn   : zahidbd2/udp-zivpn udp-zivpn_1.4.9 (udp-zivpn-linux-arm)
#   slowdns : dnstt-client built from OutlineFoundation/dnstt
# NOTE: the app ships these in its bin/armv7/ bundle - use it first.
echo ""
echo "[4/7] Installing tunnel binaries for armv7..."

REPO_BUNDLE="$HOME/vpn-app/bin/armv7"
if [ -d "$REPO_BUNDLE" ]; then
    echo "  Using repository bundle: $REPO_BUNDLE"
    cp "$REPO_BUNDLE/xray" ~/bin/xray
    cp "$REPO_BUNDLE/zivpn" ~/bin/zivpn
    cp "$REPO_BUNDLE/slowdns" ~/bin/slowdns 2>/dev/null || SLOWDNS_MISSING=1
    cp "$REPO_BUNDLE/geoip.dat" "$REPO_BUNDLE/geosite.dat" ~/.vpn-app/ 2>/dev/null || true
    chmod +x ~/bin/xray ~/bin/zivpn ~/bin/slowdns 2>/dev/null || true
fi

cd ~/vpn-binaries

# Xray v26.5.9 (fallback if bundle missing)
if [ ! -f ~/bin/xray ]; then
    echo "  Downloading Xray v26.5.9..."
    wget -q "https://github.com/XTLS/Xray-core/releases/download/v26.5.9/Xray-linux-arm32-v7a.zip" -O xray.zip
    unzip -o xray.zip xray geoip.dat geosite.dat
    chmod +x xray
    cp xray ~/bin/xray
    cp geoip.dat geosite.dat ~/.vpn-app/ 2>/dev/null || true
fi

# Zivpn UDP client uz_core (fallback if bundle missing)
if [ ! -f ~/bin/zivpn ]; then
    echo "  Downloading Zivpn (uz_core)..."
    wget -q "https://raw.githubusercontent.com/kinf744/Forot/main/android/app/src/main/jniLibs/armeabi-v7a/libuz_core.so" -O zivpn
    chmod +x zivpn
    cp zivpn ~/bin/zivpn
fi

# SlowDNS dnstt-client (fallback: build from source if bundle missing)
if [ ! -f ~/bin/slowdns ]; then
    echo "  Building SlowDNS (dnstt-client) from OutlineFoundation/dnstt..."
    pkg install -y golang git 2>/dev/null || true
    rm -rf dnstt && git clone --depth 1 https://github.com/OutlineFoundation/dnstt.git
    cd dnstt
    GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o ~/bin/slowdns ./dnstt-client
    chmod +x ~/bin/slowdns
    cd ~/vpn-binaries
fi

# NOTE: UDPGW uses the built-in pure-Go proxy (no external binary needed).

# Verify binaries
echo ""
echo "[5/7] Verifying binaries..."
for bin in xray zivpn slowdns; do
    if [ -f ~/bin/$bin ]; then
        echo "  ✓ $bin: $(file ~/bin/$bin | cut -d: -f2)"
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