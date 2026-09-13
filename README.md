# VPN App - Complete VPN Solution for Android (armeabi-v7a)

A full-featured VPN application supporting multiple tunnel protocols with a modern Web UI, designed to run on Android via Termux (armv7/armeabi-v7a architecture).

## Supported Tunnel Protocols

| Protocol | Description |
|----------|-------------|
| **SSH** | Standard SSH tunneling with SOCKS5 proxy |
| **SSH + SlowDNS** | SSH tunnel combined with DNS tunneling via SlowDNS |
| **Xray** | Xray core (VMess, VLESS, Trojan, Shadowsocks, etc.) |
| **Xray + SlowDNS** | Xray with DNS tunneling for restricted networks |
| **Zivpn** | Lightweight UDP-based VPN with obfuscation |

## Features

- **Modern Web UI** - Responsive dashboard accessible via browser
- **Multi-tunnel Management** - Run multiple tunnels simultaneously
- **Professional Features**:
  - Kill Switch (blocks traffic on disconnect)
  - Split Tunneling (route selected traffic only)
  - DNS Leak Protection
  - Auto Reconnect with configurable retries
  - UDP Gateway (UDPGW) for UDP traffic routing
- **Import/Export** - Encrypted config backup (YAML, JSON, ZIP)
- **Real-time Statistics** - Live traffic, latency, uptime monitoring
- **WebSocket Updates** - Instant UI updates without refresh
- **Dark/Light Theme** - Automatic system theme detection

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Android Device                          │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                      Termux                              │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │ │
│  │  │  VPN App     │  │  Tunnel      │  │  System      │   │ │
│  │  │  (Go)        │◄─┤  Binaries    │  │  Network     │   │ │
│  │  │  :8080       │  │  (armv7)     │  │  (TUN/IP)    │   │ │
│  │  └──────┬───────┘  └──────────────┘  └──────┬───────┘   │ │
│  │         │                                    │           │ │
│  │         ▼                                    ▼           │ │
│  │  ┌─────────────────────────────────────────────────┐    │ │
│  │  │              Web UI (Browser)                    │    │ │
│  │  └─────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start (Termux on Android)

### Prerequisites
- Android 7.0+ (API 24+)
- Termux (from F-Droid, NOT Play Store)
- Termux:Boot (for auto-start, optional)
- Root access (recommended for full functionality)

### Installation

```bash
# In Termux, run the installer:
curl -fsSL https://raw.githubusercontent.com/your-repo/vpn-app/main/scripts/install_termux.sh | bash
```

Or manually:

```bash
# 1. Update and install dependencies
pkg update && pkg upgrade -y
pkg install -y git curl wget unzip tar gzip iproute2 wireguard-tools dnsutils net-tools openssh jq tsu procps util-linux coreutils binutils clang make cmake go rust cargo

# 2. Download tunnel binaries (armv7)
mkdir -p ~/vpn-binaries && cd ~/vpn-binaries

# Xray
wget -q https://github.com/XTLS/Xray-core/releases/download/v24.8.31/Xray-linux-armv7-v3.zip
unzip -o Xray-linux-armv7-v3.zip xray
chmod +x xray && cp xray ~/bin/xray

# Zivpn
wget -q https://github.com/zaidka/zivpn/releases/download/v0.1.2/zivpn_0.1.2_linux_armv7.tar.gz
tar -xzf zivpn_0.1.2_linux_armv7.tar.gz zivpn
chmod +x zivpn && cp zivpn ~/bin/zivpn

# UDPGW (badvpn)
wget -q https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz
tar -xzf 1.999.130.tar.gz
cd badvpn-1.999.130
cmake -DCMAKE_INSTALL_PREFIX=/data/data/com.termux/files/usr -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 .
make -j$(nproc)
cp udpgw/badvpn-udpgw ~/bin/udpgw

# 3. Build VPN App
cd ~
git clone https://github.com/your-repo/vpn-app.git
cd vpn-app
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=1 go build -ldflags="-s -w" -o ~/bin/vpn-app ./cmd/vpn-app

# 4. Start
vpn-app -config ~/.vpn-app/config.yaml
```

### Access Web UI
Open browser on your Android device:
- **Local**: http://localhost:8080
- **Network**: http://<your-phone-ip>:8080

## Building from Source (Cross-compilation)

### On Linux/macOS (for armv7)

```bash
# Using the build script
./scripts/build_armv7.sh 1.0.0 $(git rev-parse --short HEAD) $(date -u +%Y-%m-%dT%H:%M:%SZ)

# Or manually
export GOOS=linux
export GOARCH=arm
export GOARM=7
export CGO_ENABLED=1
export CC=arm-linux-androideabi-gcc
go build -ldflags="-s -w -X main.version=1.0.0" -o build/armv7/vpn-app ./cmd/vpn-app
```

### Using Docker (recommended for consistent builds)

```dockerfile
# Dockerfile.armv7
FROM golang:1.23-bullseye

RUN apt-get update && apt-get install -y \
    gcc-arm-linux-gnueabihf \
    libc6-dev-armhf-cross \
    git make cmake

ENV GOOS=linux
ENV GOARCH=arm
ENV GOARM=7
ENV CGO_ENABLED=1
ENV CC=arm-linux-gnueabihf-gcc

WORKDIR /app
COPY . .
RUN go mod download && go build -ldflags="-s -w" -o vpn-app-armv7 ./cmd/vpn-app
```

```bash
docker build -f Dockerfile.armv7 -t vpn-app-armv7 .
docker run --rm -v $(pwd)/build:/app/build vpn-app-armv7
```

## Configuration

### Tunnel Configuration Examples

#### SSH Tunnel
```yaml
tunnels:
  - name: "My SSH"
    type: "ssh"
    enabled: true
    server:
      host: "ssh.example.com"
      port: 22
    auth:
      username: "user"
      password: "pass"
      # OR private_key: "/path/to/key"
```

#### SSH + SlowDNS
```yaml
tunnels:
  - name: "SSH + SlowDNS"
    type: "ssh_slowdns"
    enabled: true
    server:
      host: "ssh.example.com"
      port: 22
      public_key: "slowdns-public-key"
    auth:
      username: "user"
      private_key: "/path/to/key"
```

#### Xray (VLESS)
```yaml
tunnels:
  - name: "Xray VLESS"
    type: "xray"
    enabled: true
    server:
      host: "xray.example.com"
      port: 443
      sni: "xray.example.com"
    auth:
      uuid: "your-uuid"
      flow: "xtls-rprx-vision"
    transport:
      network: "tcp"
      security: "tls"
```

#### Xray + SlowDNS
```yaml
tunnels:
  - name: "Xray + SlowDNS"
    type: "xray_slowdns"
    enabled: true
    server:
      host: "xray.example.com"
      port: 443
      public_key: "slowdns-public-key"
      sni: "xray.example.com"
    auth:
      uuid: "your-uuid"
    transport:
      network: "ws"
      security: "tls"
      path: "/path"
```

#### Zivpn (with obfs)
```yaml
tunnels:
  - name: "Zivpn"
    type: "zivpn"
    enabled: true
    server:
      host: "zivpn.example.com"
      port: 8080
    auth:
      uuid: "your-uuid"
      password: "optional-password"
    transport:
      network: "udp"
      obfs: "plain"  # or "obfs4"
      obfs_param: "optional-param"
```

### Network Features

```yaml
features:
  kill_switch: true              # Block all traffic if VPN drops
  split_tunneling: false         # Route only selected IPs through VPN
  dns_leak_protection: true      # Force DNS through VPN
  auto_reconnect: true           # Auto-reconnect on disconnect
  reconnect_interval: 5          # Seconds between retries
  max_retries: 3                 # Max reconnection attempts

network:
  dns:
    - "1.1.1.1"
    - "8.8.8.8"
  exclude_ips:                   # Bypass VPN for these ranges
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/status` | Overall status |
| GET | `/api/v1/tunnels` | List all tunnels |
| POST | `/api/v1/tunnels` | Create tunnel |
| GET | `/api/v1/tunnels/:id` | Get tunnel details |
| PUT | `/api/v1/tunnels/:id` | Update tunnel |
| DELETE | `/api/v1/tunnels/:id` | Delete tunnel |
| POST | `/api/v1/tunnels/:id/start` | Start tunnel |
| POST | `/api/v1/tunnels/:id/stop` | Stop tunnel |
| POST | `/api/v1/tunnels/:id/restart` | Restart tunnel |
| GET | `/api/v1/features` | Get feature status |
| PUT | `/api/v1/features` | Update features |
| POST | `/api/v1/export` | Export configuration |
| POST | `/api/v1/import` | Import configuration |
| GET | `/ws` | WebSocket for real-time updates |

## Import/Export

### Export (with optional encryption)
```bash
# Via CLI
vpn-app -export config.yaml -password "your-password"

# Via Web UI
# Go to Import/Export section → Select format → Optional password → Export
```

### Import
```bash
# Via CLI
vpn-app -import config.yaml -password "your-password"

# Via Web UI
# Go to Import/Export section → Select file → Optional password → Import
```

Supported formats: YAML, JSON, ZIP (encrypted)

## Troubleshooting

### Common Issues

**"TUN device not found"**
```bash
# Requires root
su -c "mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun"
```

**"Permission denied" for IP forwarding**
```bash
su -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
```

**"Binary not found"**
```bash
# Ensure binaries are in PATH
export PATH=$PATH:/data/data/com.termux/files/home/bin
# Or use full paths in config.yaml bin_dir
```

**Web UI not accessible**
```bash
# Check if running
curl http://localhost:8080/api/v1/status
# Check firewall/SELinux
su -c "iptables -I INPUT -p tcp --dport 8080 -j ACCEPT"
```

### Logs
```bash
# View logs
tail -f ~/.vpn-app/vpn.log

# Or via Web UI → Logs section
```

## Project Structure

```
vpn-app/
├── cmd/vpn-app/           # Main entry point
├── internal/
│   ├── config/            # Configuration management
│   ├── tunnel/            # Tunnel implementations
│   │   ├── ssh_tunnel.go
│   │   ├── ssh_slowdns_tunnel.go
│   │   ├── xray_tunnel.go
│   │   ├── xray_slowdns_tunnel.go
│   │   ├── zivpn_tunnel.go
│   │   ├── udpgw.go
│   │   └── manager.go
│   ├── features/          # Professional features
│   │   ├── killswitch.go
│   │   ├── split_tunnel.go
│   │   ├── dns_leak.go
│   │   └── manager.go
│   ├── importExport/      # Import/Export functionality
│   ├── core/              # Core VPN orchestration
│   └── api/               # REST API + WebSocket
├── web/
│   ├── templates/         # HTML templates
│   └── static/            # JS/CSS assets
├── scripts/
│   ├── download_binaries.sh
│   ├── build_armv7.sh
│   └── install_termux.sh
└── build/                 # Build outputs
```

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

## Support

- Issues: GitHub Issues
- Discussions: GitHub Discussions
- Wiki: GitHub Wiki# Build trigger
