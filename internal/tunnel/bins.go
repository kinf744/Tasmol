package tunnel

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// BinDir is the directory holding the official tunnel binaries
// (xray, zivpn, slowdns, udpgw). It is set once at startup from
// App.BinDir (see core.NewVPNCore). When empty, binaries are resolved
// via PATH.
var BinDir string

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
// resolution (exec.LookPath) and finally to the bare name.
func LookupBin(binDir, name string) string {
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
