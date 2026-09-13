package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"vpn-app/internal/config"
)

type XrayTunnel struct {
	mu         sync.RWMutex
	config     *config.TunnelConfig
	status     Status
	stats      Stats
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	startTime  time.Time
	configPath string
}

func NewXrayTunnel(cfg *config.TunnelConfig) *XrayTunnel {
	return &XrayTunnel{
		config: cfg,
		status: StatusStopped,
		stats:  Stats{},
	}
}

func (t *XrayTunnel) ID() string              { return t.config.ID }
func (t *XrayTunnel) Name() string            { return t.config.Name }
func (t *XrayTunnel) Type() config.TunnelType { return config.TunnelXray }

func (t *XrayTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *XrayTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}

func (t *XrayTunnel) Config() *config.TunnelConfig { return t.config }

func (t *XrayTunnel) generateConfig() (string, error) {
	inbound := map[string]interface{}{
		"port":     10808,
		"listen":   "127.0.0.1",
		"protocol": "socks",
		"settings": map[string]interface{}{
			"udp":  true,
			"auth": "noauth",
		},
	}

	outbound := t.buildOutbound()

	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds":  []interface{}{inbound},
		"outbounds": []interface{}{outbound},
		"routing": map[string]interface{}{
			"domainStrategy": t.config.Routing.DomainStrategy,
			"rules":          t.config.Routing.Rules,
		},
		"dns": t.config.Routing.DNS,
	}

	data, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (t *XrayTunnel) buildOutbound() map[string]interface{} {
	return BuildVlessOutbound(t.config, t.config.Server.Host, t.config.Server.Port)
}

// BuildVlessOutbound builds a VLESS outbound object from a tunnel config,
// dialing addr:port. The mobile front-end reuses it with 127.0.0.1 and the
// dnstt forward port for xray_slowdns tunnels.
func BuildVlessOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	streamSettings := map[string]interface{}{
		"network":  cfg.Transport.Network,
		"security": cfg.Transport.Security,
	}

	if cfg.Transport.Network == "ws" {
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": cfg.Transport.Path,
			"headers": map[string]string{
				"Host": cfg.Transport.Host,
			},
		}
	}

	if cfg.Transport.Security == "tls" {
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    cfg.Server.SNI,
			"allowInsecure": false,
			"fingerprint":   cfg.Transport.Fingerprint,
			"alpn":          cfg.Transport.ALPN,
		}
	}

	if cfg.Transport.Security == "reality" {
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  cfg.Server.SNI,
			"publicKey":   cfg.Server.PublicKey,
			"shortId":     cfg.Server.ShortID,
			"fingerprint": cfg.Transport.Fingerprint,
		}
	}

	settings := map[string]interface{}{
		"vnext": []map[string]interface{}{
			{
				"address": addr,
				"port":    port,
				"users": []map[string]interface{}{
					{
						"id":         cfg.Auth.UUID,
						"flow":       cfg.Auth.Flow,
						"encryption": "none",
					},
				},
			},
		},
	}

	return map[string]interface{}{
		"protocol":       "vless",
		"tag":            "proxy",
		"settings":       settings,
		"streamSettings": streamSettings,
	}
}

func (t *XrayTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}

	t.status = StatusStarting
	t.setError("")

	configContent, err := t.generateConfig()
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	tmpDir, _ := os.MkdirTemp("", "xray-*")
	t.configPath = filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(t.configPath, []byte(configContent), 0644); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	ctx, t.cancel = context.WithCancel(ctx)
	t.cmd = exec.CommandContext(ctx, LookupBin(BinDir, BinXray), "run", "-config", t.configPath)
	if BinDir != "" {
		t.cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+BinDir)
	}

	if err := t.cmd.Start(); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("failed to start Xray: %w", err)
	}

	t.startTime = time.Now()
	t.status = StatusRunning

	go t.monitorProcess()

	return nil
}

func (t *XrayTunnel) Stop(ctx context.Context) error {
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

func (t *XrayTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *XrayTunnel) monitorProcess() {
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

func (t *XrayTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
