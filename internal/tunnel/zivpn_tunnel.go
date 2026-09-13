package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpn-app/internal/config"
)

// ZivpnTunnel drives the official udp-zivpn binary (zahidbd2/udp-zivpn
// release udp-zivpn_1.4.9, udp-zivpn-linux-arm) in client mode:
//
//	zivpn client --config <client.json>
//
// The client exposes a local SOCKS5 proxy (default 127.0.0.1:10810) used
// as the device upstream. Server port defaults to 5667 (official server
// listen port). TLS is insecure by default because official install
// scripts generate self-signed certificates (override with
// Advanced["tls_insecure"]=false).
//
// Obfuscation mapping (Hysteria2-derived protocol): Transport.Obfs sets the
// obfs type (default "salamander" to match the official server
// "obfs":"zivpn"), Transport.ObfsParam sets the obfs password (default
// "zivpn"). Advanced["obfs_raw"] may hold a raw JSON value injected
// verbatim as the "obfs" field for fork variants.
type ZivpnTunnel struct {
	mu         sync.RWMutex
	config     *config.TunnelConfig
	status     Status
	stats      Stats
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	startTime  time.Time
	configPath string
	dialPort   int
}

func NewZivpnTunnel(cfg *config.TunnelConfig) *ZivpnTunnel {
	return &ZivpnTunnel{
		config: cfg,
		status: StatusStopped,
		stats:  Stats{},
	}
}

func (t *ZivpnTunnel) ID() string              { return t.config.ID }
func (t *ZivpnTunnel) Name() string            { return t.config.Name }
func (t *ZivpnTunnel) Type() config.TunnelType { return config.TunnelZivpn }

func (t *ZivpnTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *ZivpnTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}

func (t *ZivpnTunnel) Config() *config.TunnelConfig { return t.config }

func (t *ZivpnTunnel) serverPort() int {
	if t.dialPort != 0 {
		return t.dialPort
	}
	if t.config.Server.PortRange != "" {
		if port, err := PickPortFromRange(t.config.Server.PortRange); err == nil {
			return port
		}
	}
	if t.config.Server.Port != 0 {
		return t.config.Server.Port
	}
	return 5667
}

// PickPortFromRange parses "5667" or "6000-19999" (Zivpn UDP accounts) and
// returns the port to dial (random within a range, for load spreading).
func PickPortFromRange(pr string) (int, error) {
	pr = strings.TrimSpace(pr)
	if pr == "" {
		return 0, fmt.Errorf("empty port range")
	}
	if !strings.Contains(pr, "-") {
		port, err := strconv.Atoi(pr)
		if err != nil || port <= 0 || port > 65535 {
			return 0, fmt.Errorf("invalid port %q", pr)
		}
		return port, nil
	}
	parts := strings.SplitN(pr, "-", 2)
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo <= 0 || hi > 65535 || lo > hi {
		return 0, fmt.Errorf("invalid port range %q (expected LO-HI)", pr)
	}
	if lo == hi {
		return lo, nil
	}
	return lo + rand.IntN(hi-lo+1), nil
}

func (t *ZivpnTunnel) socksPort() int {
	return advInt(t.config.Advanced, "socks_port", 10810)
}

func (t *ZivpnTunnel) authPassword() string {
	if t.config.Auth.Password != "" {
		return t.config.Auth.Password
	}
	return "zi"
}

func (t *ZivpnTunnel) obfsType() string {
	// Hardcoded: the official udp-zivpn server uses salamander obfuscation.
	// (No UI field; Advanced["obfs_raw"] may still inject a raw block.)
	return "salamander"
}

func (t *ZivpnTunnel) obfsPassword() string {
	// Hardcoded: matches the official server "obfs":"zivpn".
	return "zivpn"
}

func (t *ZivpnTunnel) sni() string {
	if t.config.Server.SNI != "" {
		return t.config.Server.SNI
	}
	return t.config.Server.Host
}

// generateClientConfig builds the client.json consumed by
// `zivpn client --config`.
func (t *ZivpnTunnel) generateClientConfig() (string, error) {
	var obfs interface{}
	if raw, ok := t.config.Advanced["obfs_raw"].(string); ok && raw != "" {
		var v interface{}
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return "", fmt.Errorf("invalid obfs_raw JSON: %w", err)
		}
		obfs = v
	} else {
		// Standard Hysteria2-style salamander block. The nested key must be
		// the obfs type name (e.g. "salamander").
		obfs = map[string]interface{}{
			"type": t.obfsType(),
			t.obfsType(): map[string]interface{}{
				"password": t.obfsPassword(),
			},
		}
	}

	clientCfg := map[string]interface{}{
		"server": fmt.Sprintf("%s:%d", t.config.Server.Host, t.serverPort()),
		"auth": map[string]interface{}{
			"mode":     "password",
			"password": t.authPassword(),
		},
		"tls": map[string]interface{}{
			"sni":      t.sni(),
			"insecure": advBool(t.config.Advanced, "tls_insecure", true),
		},
		"obfs": obfs,
		"socks5": map[string]interface{}{
			"listen": fmt.Sprintf("127.0.0.1:%d", t.socksPort()),
		},
		"bandwidth": map[string]interface{}{
			"up":   advStr(t.config.Advanced, "up_mbps", "50 mbps"),
			"down": advStr(t.config.Advanced, "down_mbps", "200 mbps"),
		},
	}

	data, err := json.MarshalIndent(clientCfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (t *ZivpnTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}

	if t.config.Server.Host == "" {
		return fmt.Errorf("zivpn server host is required (server.host)")
	}

	t.status = StatusStarting
	t.setError("")

	if t.config.Server.PortRange != "" {
		port, err := PickPortFromRange(t.config.Server.PortRange)
		if err != nil {
			t.status = StatusError
			t.setError(err.Error())
			return err
		}
		t.dialPort = port
	} else {
		t.dialPort = 0
	}

	configContent, err := t.generateClientConfig()
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	tmpDir, err := os.MkdirTemp("", "zivpn-*")
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.configPath = filepath.Join(tmpDir, "client.json")
	if err := os.WriteFile(t.configPath, []byte(configContent), 0600); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	ctx, t.cancel = context.WithCancel(ctx)
	t.cmd = exec.CommandContext(ctx,
		LookupBin(BinDir, BinZivpn), "client", "--config", t.configPath)

	if err := t.cmd.Start(); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("failed to start Zivpn client: %w", err)
	}

	// Wait until the local SOCKS5 is exposed before reporting running.
	t.mu.Unlock()
	socksErr := waitForTCP(fmt.Sprintf("127.0.0.1:%d", t.socksPort()), 20*time.Second)
	t.mu.Lock()

	if socksErr != nil {
		t.cmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("Zivpn SOCKS not ready: %v", socksErr))
		return fmt.Errorf("zivpn socks not ready: %w", socksErr)
	}

	t.startTime = time.Now()
	t.status = StatusRunning

	go t.monitorProcess()

	return nil
}

func (t *ZivpnTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}

	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}

	if t.configPath != "" {
		os.Remove(t.configPath)
		os.Remove(filepath.Dir(t.configPath))
	}

	t.status = StatusStopped
	return nil
}

func (t *ZivpnTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *ZivpnTunnel) monitorProcess() {
	err := t.cmd.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		t.status = StatusError
		if err != nil {
			t.setError(err.Error())
		}
	}
}

func (t *ZivpnTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
