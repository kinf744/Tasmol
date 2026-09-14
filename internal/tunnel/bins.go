package tunnel

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"vpn-app/internal/config"
)

// BinDir is the directory holding the official tunnel binaries
// (xray, zivpn, slowdns, udpgw). It is set once at startup from
// App.BinDir (see core.NewVPNCore). When empty, binaries are resolved
// via PATH.
var BinDir string

// BinNames optionally remaps logical binary names to on-disk file names.
// The Android APK ships the official binaries as native libraries
// (lib_xray.so, ...), so mobile mode sets:
// BinNames = {"xray":"lib_xray.so", "zivpn":"lib_zivpn.so", "slowdns":"lib_slowdns.so"}.
var BinNames map[string]string

// NativeSSH selects the pure-Go SSH implementation (golang.org/x/crypto/ssh
// + embedded SOCKS5 server) instead of the external openssh binary. The APK
// cannot rely on an openssh binary, so mobile mode enables this.
var NativeSSH bool

// LogFunc is an optional sink for verbose tunnel activity. vpnlib wires it
// to a file (Download/kighmu.txt) so connection failures can be diagnosed in
// real time. nil = logging disabled.
var LogFunc func(format string, args ...interface{})

// Tracef appends a timestamped line to the tunnel activity log.
func Tracef(format string, args ...interface{}) {
	if LogFunc == nil {
		return
	}
	LogFunc(format, args...)
}

// Binary names as stored in bin/armv7/ of the repository.
const (
	BinSSH     = "ssh"
	BinSlowDNS = "slowdns"
	BinXray    = "xray"
	BinZivpn   = "zivpn"
	BinUDPGW   = "udpgw"
)

// LookupBin returns the executable path for a tunnel binary: it prefers
// <binDir>/<name> when that file exists, otherwise it falls back to PATH
// resolution (exec.LookPath) and finally to the bare name. BinNames remaps
// the logical name to the on-disk name (Android native libraries).
func LookupBin(binDir, name string) string {
	if mapped, ok := BinNames[name]; ok && mapped != "" {
		name = mapped
	}
	if binDir == "" {
		binDir = BinDir
	}
	if binDir != "" {
		p := filepath.Join(binDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// Default local SOCKS5 ports exposed by each tunnel type. They double as
// the tun2socks upstream endpoints on mobile. Overridable per tunnel via
// Advanced["socks_port"].
const (
	DefaultSSHPort         = 10801
	DefaultSSHSlowDNSPort  = 10802
	DefaultXrayPort        = 10808
	DefaultXraySlowDNSPort = 10809
	DefaultZivpnPort       = 10810
)

// SocksPort returns the local SOCKS5 port a tunnel exposes.
func SocksPort(cfg *config.TunnelConfig) int {
	switch cfg.Type {
	case config.TunnelSSH:
		return advInt(cfg.Advanced, "socks_port", DefaultSSHPort)
	case config.TunnelSSHSlowDNS:
		return advInt(cfg.Advanced, "socks_port", DefaultSSHSlowDNSPort)
	case config.TunnelXray:
		return advInt(cfg.Advanced, "socks_port", DefaultXrayPort)
	case config.TunnelXraySlowDNS:
		return advInt(cfg.Advanced, "socks_port", DefaultXraySlowDNSPort)
	case config.TunnelZivpn:
		return advInt(cfg.Advanced, "socks_port", DefaultZivpnPort)
	default:
		return advInt(cfg.Advanced, "socks_port", DefaultXrayPort)
	}
}

// SocksAddr returns the local SOCKS5 endpoint a tunnel exposes, used by the
// mobile data plane (Xray front upstream) and by SOCKS-aware clients.
func SocksAddr(cfg *config.TunnelConfig) string {
	return fmt.Sprintf("127.0.0.1:%d", SocksPort(cfg))
}

// waitForTCP polls addr until a TCP connection succeeds or timeout elapses.
// It is used to wait for a forwarder (dnstt, SOCKS) to be ready before
// starting the next stage of a chained tunnel.
func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s: %w", addr, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// advInt reads an int override from the tunnel Advanced map.
// JSON-decoded numbers arrive as float64; plain strings are accepted too.
func advInt(m map[string]interface{}, key string, def int) int {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		if p, err := strconv.Atoi(n); err == nil {
			return p
		}
	}
	return def
}

// advStr reads a string override from the tunnel Advanced map.
func advStr(m map[string]interface{}, key string, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return def
}

// advBool reads a bool override from the tunnel Advanced map.
func advBool(m map[string]interface{}, key string, def bool) bool {
	if m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
		if s, ok := v.(string); ok {
			if p, err := strconv.ParseBool(s); err == nil {
				return p
			}
		}
	}
	return def
}
