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

var BinDir string

var BinNames map[string]string

var NativeSSH bool

var TCPNoDelay = true

var DnsttUseTCP = false

var DNSPrimary string
var DNSSecondary string

var TmpDir string

var LogFunc func(format string, args ...interface{})

var QuietLog = true

func errorish(s string) bool {
	l := strings.ToLower(s)
	for _, n := range []string{"error", "fail", "refused", "timeout", "timed out",
		"denied", "panic", "fatal", "critical", "unreachable", "invalid"} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

var logFileName = string([]rune{107, 105, 103, 104, 109, 117, 46, 116, 120, 116})

func LogFileName() string { return logFileName }

var DirectLog func(line string)

func directLog(format string, args ...interface{}) {
	if DirectLog == nil {
		return
	}
	DirectLog(fmt.Sprintf(format, args...))
}

func Tracef(format string, args ...interface{}) {
	if QuietLog {
		return
	}
	if LogFunc != nil {

		LogFunc(format, args...)
		return
	}

	if DirectLog != nil {
		DirectLog(fmt.Sprintf(format, args...))
	}
}

func logLine(level, component, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	comp := strings.ReplaceAll(strings.ReplaceAll(component, "[", ""), "]", "")
	line := "[" + level + "] [" + comp + "] " + msg
	if LogFunc != nil {
		LogFunc("%s", line)
		return
	}

	directLog("%s", line)
}

func Infof(component, format string, args ...interface{}) {
	if QuietLog {
		return
	}
	logLine("info", component, format, args...)
}

func Connf(component, format string, args ...interface{}) {
	logLine("connection", component, format, args...)
}

func Journalf(component, format string, args ...interface{}) {
	logLine("journal", component, format, args...)
}

func Warnf(component, format string, args ...interface{}) {
	logLine("warning", component, format, args...)
}

func Errorf(component, format string, args ...interface{}) {
	if QuietLog {
		return
	}
	// Nettoyer le préfixe du composant des messages d'erreur pour éviter les doublons
	// (ex: "ssh handshake failed: ssh: handshake failed: EOF" -> "ssh handshake failed: handshake failed: EOF").
	prefix := component + ": "
	for i, a := range args {
		switch v := a.(type) {
		case error:
			msg := strings.TrimPrefix(v.Error(), prefix)
			args[i] = fmt.Errorf("%s", msg)
		case string:
			args[i] = strings.TrimPrefix(v, prefix)
		}
	}
	logLine("error", component, format, args...)
}

const (
	BinSSH      = "ssh"
	BinSlowDNS  = "slowdns"
	BinXray     = "xray"
	BinZivpn    = "zivpn"
	BinHysteria = "hysteria"
	BinUDPGW    = "udpgw"
)

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

const (
	DefaultSSHPort         = 10801
	DefaultSSHSlowDNSPort  = 10802
	DefaultXrayPort        = 10808
	DefaultXraySlowDNSPort = 10809
	DefaultZivpnPort       = 10810
	DefaultHysteriaPort    = 10811
)

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
	case config.TunnelHysteria:
		return advInt(cfg.Advanced, "socks_port", DefaultHysteriaPort)
	default:
		return advInt(cfg.Advanced, "socks_port", DefaultXrayPort)
	}
}

var liveSocks sync.Map

var liveFwd sync.Map

func SetLiveForward(id string, port int) { liveFwd.Store(id, port) }

func ClearLiveForward(id string) { liveFwd.Delete(id) }

func LiveForward(id string) int {
	v, ok := liveFwd.Load(id)
	if !ok {
		return 0
	}
	p, _ := v.(int)
	return p
}

func androidCAEnv() []string {
	if st, err := os.Stat("/system/etc/security/cacerts"); err == nil && st.IsDir() {
		return []string{"SSL_CERT_DIR=/system/etc/security/cacerts"}
	}
	return nil
}

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

func PickFreePort() (int, error) {
	return pickFreePort()
}

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

func SetLiveSocksAddr(id, addr string) { liveSocks.Store(id, addr) }

func ClearLiveSocksAddr(id string) { liveSocks.Delete(id) }

func LiveSocksAddr(id string) string {
	v, ok := liveSocks.Load(id)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

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

func SocksAddr(cfg *config.TunnelConfig) string {
	if cfg != nil {
		if live := LiveSocksAddr(cfg.ID); live != "" {
			return live
		}
	}
	return fmt.Sprintf("127.0.0.1:%d", SocksPort(cfg))
}

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

func setNoDelay(c net.Conn) {
	if !TCPNoDelay {
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
}

func waitForTCP(addr string, timeout time.Duration) error {
	return waitForTCPctx(context.Background(), addr, timeout)
}

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
