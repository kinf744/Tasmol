package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// TCPNoDelay enables TCP_NODELAY on relayed sockets (lower latency,
// slightly more packets). Wired from Settings.
var TCPNoDelay = true

// DnsttUseTCP makes SlowDNS use -tcp instead of -udp toward the resolver
// ("Boost SlowDNS"): carriers that throttle/filter UDP DNS get a faster,
// more reliable tunnel over TCP.
var DnsttUseTCP = false

// DNSPrimary/DNSSecondary feed generated Xray dns sections (Settings,
// custom DNS). Empty = defaults 1.1.1.1/8.8.8.8.
var DNSPrimary string
var DNSSecondary string

// TmpDir is a writable app-private directory (Android cache dir) for
// temp tunnel configs. Android has no /tmp and the process CWD is
// read-only, so os.MkdirTemp("") fails there.
var TmpDir string

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

// Leveled journal: every line carries [level] [component] so the UI colors
// milestones, warnings and errors (info/connection/warning/error).
// Secrets are masked at write time by the file logger.
func logLine(level, component, format string, args ...interface{}) {
	if LogFunc == nil {
		return
	}
	comp := strings.ReplaceAll(strings.ReplaceAll(component, "[", ""), "]", "")
	LogFunc("[" + level + "] [" + comp + "] " + fmt.Sprintf(format, args...))
}

// Infof logs a routine journal line.
func Infof(component, format string, args ...interface{}) {
	logLine("info", component, format, args...)
}

// Connf logs a connection milestone (helper up, session running, switch).
func Connf(component, format string, args ...interface{}) {
	logLine("connection", component, format, args...)
}

// Journalf logs one concise journal step: the in-app Journal view shows
// journal+connection+warning+error only (the full firehose stays available
// in Verbose mode). One line per real tunnel step, no internals.
func Journalf(component, format string, args ...interface{}) {
	logLine("journal", component, format, args...)
}

// Warnf logs a suspicious but non-fatal journal line.
func Warnf(component, format string, args ...interface{}) {
	logLine("warning", component, format, args...)
}

// Errorf logs a failure journal line.
func Errorf(component, format string, args ...interface{}) {
	logLine("error", component, format, args...)
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
			Tracef("[bins] resolved %q -> %q", name, p)
			return p
		}
		// Some devices nest ABI dirs under nativeLibraryDir.
		for _, arch := range []string{"arm", "armeabi-v7a", "arm64-v8a", "x86", "x86_64"} {
			p := filepath.Join(binDir, arch, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				Tracef("[bins] resolved %q -> %q (abi subdir %q)", name, p, arch)
				return p
			}
		}
		Tracef("[bins] %q NOT found under %q", name, binDir)
	}
	if p, err := exec.LookPath(name); err == nil {
		Tracef("[bins] resolved %q via PATH -> %q", name, p)
		return p
	}
	Tracef("[bins] %q unresolved, returning bare name", name)
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

// liveSocks maps tunnel ID -> actual local SOCKS endpoint of the RUNNING
// session. Sessions bind fresh random ports per start, so a previous
// session's listener — still draining or leaked by a wedged teardown — can
// never collide with a reconnect. Consumers (data plane, RR front, ping)
// must resolve through SocksAddr/SocksPortLive, never the static default.
var liveSocks sync.Map // string -> string

// liveFwd maps tunnel ID -> live dnstt forward port of the running session
// (ssh_slowdns / xray_slowdns). Same per-session randomness rationale as
// liveSocks: two profiles of the same type must never share 2222/2224.
var liveFwd sync.Map // string -> int

// SetLiveForward publishes the live dnstt forward port of a session.
func SetLiveForward(id string, port int) { liveFwd.Store(id, port) }

// ClearLiveForward removes the live forward entry (session stopped).
func ClearLiveForward(id string) { liveFwd.Delete(id) }

// LiveForward returns the published live forward port, or 0 if none.
func LiveForward(id string) int {
	v, ok := liveFwd.Load(id)
	if !ok {
		return 0
	}
	p, _ := v.(int)
	return p
}

// androidCAEnv returns SSL_CERT_DIR pointing at Android's system CA store.
// The bundled xray is a linux/arm build: on Android, Go's linux x509 loader
// looks for roots in /etc/ssl/certs & co. — none exist inside the app
// sandbox — so EVERY TLS outbound fails with "certificate signed by
// unknown authority". Go honors SSL_CERT_DIR, and Android keeps its root
// CAs (OpenSSL-hashed files, the exact format the loader expects) in
// /system/etc/security/cacerts, which is world-readable. This restores
// real certificate verification for all TLS outbounds; the live-chain
// pinning (pinnedPeerCertSha256) stays as an extra layer.
func androidCAEnv() []string {
	if st, err := os.Stat("/system/etc/security/cacerts"); err == nil && st.IsDir() {
		return []string{"SSL_CERT_DIR=/system/etc/security/cacerts"}
	}
	return nil
}

// XrayDNSServers returns the custom DNS pair for generated xray configs
// (Settings), falling back per entry when invalid.
func XrayDNSServers() []string {
	p := strings.TrimSpace(DNSPrimary)
	if net.ParseIP(p) == nil {
		p = "1.1.1.1"
	}
	s := strings.TrimSpace(DNSSecondary)
	if net.ParseIP(s) == nil {
		s = "8.8.8.8"
	}
	return []string{p, s}
}

// PickFreePort asks the kernel for a free loopback TCP port (exported
// wrapper around pickFreePort for the vpnlib front builder).
func PickFreePort() (int, error) {
	return pickFreePort()
}

// PickLiveSocksAddr returns the SOCKS endpoint a session must bind: the
// explicit Advanced["socks_port"] override when set, otherwise a fresh
// random loopback port. The choice is published in the live registry so
// the data plane, the RR front, the status and the ping helper always dial
// the live port. Sessions never reuse ports: a previous session's
// listener — draining or leaked — can never collide.
func PickLiveSocksAddr(cfg *config.TunnelConfig) (string, int, error) {
	if cfg != nil {
		if p := advInt(cfg.Advanced, "socks_port", 0); p > 0 {
			if err := waitPortFree(p, 3*time.Second); err != nil {
				return "", 0, err
			}
			addr := fmt.Sprintf("127.0.0.1:%d", p)
			SetLiveSocksAddr(cfg.ID, addr)
			return addr, p, nil
		}
	}
	var port int
	for attempt := 0; attempt < 5; attempt++ {
		p, err := pickFreePort()
		if err != nil {
			continue
		}
		if waitPortFree(p, time.Second) == nil {
			port = p
			break
		}
	}
	if port == 0 {
		p, err := pickFreePort()
		if err != nil {
			return "", 0, err
		}
		port = p
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if cfg != nil && cfg.ID != "" {
		SetLiveSocksAddr(cfg.ID, addr)
	}
	return addr, port, nil
}

// PickLiveForward returns the dnstt forward port a session must use: the
// explicit Advanced["fwd_port"] override when set, otherwise a fresh
// random loopback port, published via SetLiveForward.
func PickLiveForward(cfg *config.TunnelConfig, def int) (int, error) {
	if cfg != nil {
		if p := advInt(cfg.Advanced, "fwd_port", 0); p > 0 {
			if err := waitPortFree(p, 3*time.Second); err != nil {
				return 0, err
			}
			SetLiveForward(cfg.ID, p)
			return p, nil
		}
	}
	var port int
	for attempt := 0; attempt < 5; attempt++ {
		p, err := pickFreePort()
		if err != nil {
			continue
		}
		if waitPortFree(p, time.Second) == nil {
			port = p
			break
		}
	}
	if port == 0 {
		p, err := pickFreePort()
		if err != nil {
			return 0, err
		}
		port = p
	}
	_ = def
	if cfg != nil && cfg.ID != "" {
		SetLiveForward(cfg.ID, port)
	}
	return port, nil
}

// SetLiveSocksAddr publishes the live SOCKS endpoint of a running session.
func SetLiveSocksAddr(id, addr string) { liveSocks.Store(id, addr) }

// ClearLiveSocksAddr removes the live endpoint (session stopped).
func ClearLiveSocksAddr(id string) { liveSocks.Delete(id) }

// LiveSocksAddr returns the published live endpoint, or "" if none.
func LiveSocksAddr(id string) string {
	v, ok := liveSocks.Load(id)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// SocksPortLive returns the live SOCKS port of a running session, falling
// back to the static configured/default port when the tunnel is stopped.
func SocksPortLive(cfg *config.TunnelConfig) int {
	if cfg != nil {
		if live := LiveSocksAddr(cfg.ID); live != "" {
			if h, p, err := net.SplitHostPort(live); err == nil && h != "" {
				if port, perr := strconv.Atoi(p); perr == nil && port > 0 {
					return port
				}
			}
		}
	}
	return SocksPort(cfg)
}

// SocksAddr returns the local SOCKS5 endpoint a tunnel exposes, used by the
// mobile data plane (Xray front upstream) and by SOCKS-aware clients.
// It resolves to the LIVE session port when the tunnel runs.
func SocksAddr(cfg *config.TunnelConfig) string {
	if cfg != nil {
		if live := LiveSocksAddr(cfg.ID); live != "" {
			return live
		}
	}
	return fmt.Sprintf("127.0.0.1:%d", SocksPort(cfg))
}

// relayTCP bidirectionally copies between a and b, half-closing each
// direction independently. A plain full-close on first EOF would RST a peer
// that may still deliver data (notably the uz SOCKS server, which logs
// "connection reset by peer" otherwise).
func relayTCP(a, b net.Conn) {
	setNoDelay(a)
	setNoDelay(b)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	<-done
	<-done
	a.Close()
	b.Close()
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	c.Close()
}

// setNoDelay enables TCP_NODELAY when the setting allows it.
func setNoDelay(c net.Conn) {
	if !TCPNoDelay {
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
}

// waitForTCP polls addr until a TCP connection succeeds or timeout elapses.
// It is used to wait for a forwarder (dnstt, SOCKS) to be ready before
// starting the next stage of a chained tunnel.
func waitForTCP(addr string, timeout time.Duration) error {
	return waitForTCPctx(context.Background(), addr, timeout)
}

// waitForTCPctx is waitForTCP aborting promptly when ctx is cancelled, so
// a disconnect during a chained start never blocks teardown on full
// readiness budgets (that delay once produced stuck-disconnect reports).
func waitForTCPctx(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("aborted waiting for %s: %w", addr, ctx.Err())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s: %w", addr, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("aborted waiting for %s: %w", addr, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
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
