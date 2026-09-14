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
- **Round-robin multi-profile (Android)** - Select 2+ profiles and the
  session rotates across them with **Xray's built-in `roundrobin`
  balancer** (verified in Xray-core v26.5.9 `app/router`): each selected
  profile is started (3 connection attempts, failures are skipped), then a
  local Xray SOCKS front (`127.0.0.1:10900`) distributes every TCP/UDP
  connection across the survivors. Any tunnel type can join (SSH/Zivpn via
  their local SOCKS helpers, Xray via native outbounds). With a single
  profile the balancer is never initialized (direct upstream). Dead
  profiles are revived/expelled live by the follow loop.

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

# 2. Install official tunnel binaries (armv7) - stored in the repo bundle bin/armv7/
mkdir -p ~/bin ~/.vpn-app && cd ~/vpn-app 2>/dev/null || cd ~

# Xray v26.5.9 (XTLS/Xray-core, Xray-linux-arm32-v7a.zip)
cp bin/armv7/xray ~/bin/xray
cp bin/armv7/geoip.dat bin/armv7/geosite.dat ~/.vpn-app/

# Zivpn udp-zivpn_1.4.9 (zahidbd2/udp-zivpn, udp-zivpn-linux-arm, client mode)
cp bin/armv7/zivpn ~/bin/zivpn

# SlowDNS dnstt-client (built from OutlineFoundation/dnstt, stored in bundle)
cp bin/armv7/slowdns ~/bin/slowdns

chmod +x ~/bin/xray ~/bin/zivpn ~/bin/slowdns

# (Fallback without the repo bundle: scripts/download_binaries.sh
#  downloads Xray v26.5.9 + zivpn 1.4.9 from official releases and
#  builds dnstt-client from OutlineFoundation/dnstt.)
# NOTE: UDPGW uses the built-in pure-Go proxy - no external binary needed.

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

#### SSH (username, password, payload, proxy)
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
    ssh:
      proxy: "127.0.0.1:8080"   # optional HTTP CONNECT hop (ip:port)
      payload: |                 # optional payload template
        GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]
    # tokens: [crlf] [lf] [host] [port] [proxy_host] [proxy_port]
    # NOTE: proxy/payload need the native SSH engine (mobile default;
    # server mode: advanced.native_ssh=true). No transport section.
```

#### SSH + SlowDNS (username, password, dns, NS, pubkey)
```yaml
tunnels:
  - name: "SSH + SlowDNS"
    type: "ssh_slowdns"
    enabled: true
    server:
      nameserver: "ns.example.com" # dnstt zone domain (required)
      public_key: "<64-hex-dnstt-pubkey>"  # (required)
      dns_resolver: "8.8.8.8:53"   # resolver with port (required)
    auth:
      username: "user"
      password: "pass"
    ssh:
      proxy: ""                    # ignored for slowdns (dnstt is the hop)
      payload: ""
    # advanced overrides: fwd_port (default 2222), socks_port (default 10802)
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

#### Xray (link OR JSON only)
The Xray form shows exactly two fields: **subscription link**
(`vmess://`, `vless://`, `trojan://`, `ss://`) and **outbound JSON**.
Mechanism: paste a link + **Parse link** (fills the JSON box), or paste
the JSON directly — the JSON box wins at runtime when non-empty.
```yaml
tunnels:
  - name: "Xray link"
    type: "xray"
    enabled: true
    advanced:
      link: "vless://uuid@host:443?security=tls&sni=host#name"
      outbound_json: '{"protocol":"vless",...}'  # from Parse, or pasted
```
Transports supported by Xray/Xray-SlowDNS tunnels: `tcp`, `ws`, `grpc`,
`xhttp`, `httpupgrade` (+ `tls`/`reality` security).

#### Xray + SlowDNS (dnstt-client + xray v26.5.9)
Fields: link (vmess/vless/trojan/ss), DNS resolver with port
(e.g. `8.8.8.8:53`), NS domain, public key.
```yaml
tunnels:
  - name: "Xray + SlowDNS"
    type: "xray_slowdns"
    enabled: true
    server:
      host: "xray.example.com"     # informational (Xray dials 127.0.0.1 via dnstt)
      nameserver: "ns.example.com" # dnstt zone domain (required)
      public_key: "<64-hex-dnstt-pubkey>"  # (required)
      dns_resolver: "8.8.8.8"
      sni: "xray.example.com"
    auth:
      uuid: "your-uuid"
    transport:
      network: "ws"
      security: "tls"
      path: "/path"
    # advanced overrides: fwd_port (default 2224), socks_port (default 10809)
```

#### Zivpn UDP (uz_core client, reference architecture)
Fields: IP/Host, Port range(s) (e.g. `6000-19999`, comma-separated
supported), Password. No transport/obfs fields (hardcoded in source).

Architecture (mirrors the proven reference app): the hostname is resolved
to IP, then **one `uz_core` process per port range** is spawned:

    zivpn -s <obfs> --config '<inline-json>'

with the flat client JSON the binary expects:

```json
{"server":"<ip>:<range>","obfs":"hu``hqb`c","auth":"<password>",
 "socks5":{"listen":"127.0.0.1:<uzPort>"},"insecure":true,
 "recvwindowconn":65536,"recvwindow":262144,
 "disable_mtu_discovery":true,"down_mbps":50,"up_mbps":10}
```

A round-robin TCP balancer unifies the uz SOCKS endpoints on the tunnel
SOCKS port (default `:10810`, `Advanced["socks_port"]` override). Each
session picks fresh random loopback ports for the uz listeners, so an
immediate reconnect can never collide with a previous session's sockets.

```yaml
tunnels:
  - name: "Zivpn"
    type: "zivpn"
    enabled: true
    server:
      host: "zivpn.example.com"
      port_range: "6000-19999"  # comma-separated ranges supported
    auth:
      password: "zi"   # server password (default "zi")
    # obfs "hu``hqb`c" (salamander) is hardcoded in the app source.
    # advanced overrides: socks_port (default 10810),
    #   tls_insecure (default true, self-signed server certs),
    #   up_mbps/down_mbps (defaults "50 mbps"/"200 mbps"),
    #   obfs_raw (raw JSON injected as "obfs" for fork variants)
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
#
