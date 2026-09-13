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

type XraySlowDNSTunnel struct {
	mu           sync.RWMutex
	config       *config.TunnelConfig
	status       Status
	stats        Stats
	xrayCmd      *exec.Cmd
	slowdnscmd   *exec.Cmd
	cancel       context.CancelFunc
	startTime    time.Time
	configPath   string
	localPort    int
	dnsServer    string
}

func NewXraySlowDNSTunnel(cfg *config.TunnelConfig) *XraySlowDNSTunnel {
	return &XraySlowDNSTunnel{
		config:     cfg,
		status:     StatusStopped,
		stats:      Stats{},
		localPort:  10808,
		dnsServer:  "8.8.8.8",
	}
}

func (t *XraySlowDNSTunnel) ID() string        { return t.config.ID }
func (t *XraySlowDNSTunnel) Name() string      { return t.config.Name }
func (t *XraySlowDNSTunnel) Type() config.TunnelType { return config.TunnelXraySlowDNS }

func (t *XraySlowDNSTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *XraySlowDNSTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}

func (t *XraySlowDNSTunnel) Config() *config.TunnelConfig { return t.config }

func (t *XraySlowDNSTunnel) generateXrayConfig() (string, error) {
	inbound := map[string]interface{}{
		"port":     t.localPort,
		"listen":   "127.0.0.1",
		"protocol": "socks",
		"settings": map[string]interface{}{
			"udp": true,
			"auth": "noauth",
		},
	}

	outbound := map[string]interface{}{
		"protocol": "freedom",
		"tag":      "direct",
	}

	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []interface{}{inbound},
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

func (t *XraySlowDNSTunnel) buildSlowDNSArgs() []string {
	args := []string{
		"-udp",
		"-listen", fmt.Sprintf("127.0.0.1:%d", t.localPort+1),
		"-dns", t.dnsServer,
		"-pubkey", t.config.Server.PublicKey,
		"-nameserver", t.config.Server.Host,
	}

	if t.config.Server.Port != 0 {
		args = append(args, "-port", fmt.Sprintf("%d", t.config.Server.Port))
	}

	return args
}

func (t *XraySlowDNSTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}

	t.status = StatusStarting
	t.setError("")

	configContent, err := t.generateXrayConfig()
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	tmpDir, _ := os.MkdirTemp("", "xray-slowdns-*")
	t.configPath = filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(t.configPath, []byte(configContent), 0644); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	ctx, t.cancel = context.WithCancel(ctx)

	t.xrayCmd = exec.CommandContext(ctx, "xray", "run", "-config", t.configPath)
	if err := t.xrayCmd.Start(); err != nil {
		t.status = StatusError
		t.setError(fmt.Sprintf("Xray start failed: %v", err))
		return fmt.Errorf("failed to start Xray: %w", err)
	}

	time.Sleep(1 * time.Second)

	slowdnsArgs := t.buildSlowDNSArgs()
	t.slowdnscmd = exec.CommandContext(ctx, "slowdns", slowdnsArgs...)
	if err := t.slowdnscmd.Start(); err != nil {
		t.xrayCmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("SlowDNS start failed: %v", err))
		return fmt.Errorf("failed to start SlowDNS: %w", err)
	}

	t.startTime = time.Now()
	t.status = StatusRunning

	go t.monitorProcesses()

	return nil
}

func (t *XraySlowDNSTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}

	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.xrayCmd != nil && t.xrayCmd.Process != nil {
		t.xrayCmd.Process.Kill()
		t.xrayCmd.Wait()
	}

	if t.slowdnscmd != nil && t.slowdnscmd.Process != nil {
		t.slowdnscmd.Process.Kill()
		t.slowdnscmd.Wait()
	}

	if t.configPath != "" {
		os.Remove(t.configPath)
		os.Remove(filepath.Dir(t.configPath))
	}

	t.status = StatusStopped
	return nil
}

func (t *XraySlowDNSTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *XraySlowDNSTunnel) monitorProcesses() {
	xrayErr := t.xrayCmd.Wait()
	slowdnsErr := t.slowdnscmd.Wait()

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		t.status = StatusError
		if xrayErr != nil {
			t.setError(fmt.Sprintf("Xray: %v", xrayErr))
		} else if slowdnsErr != nil {
			t.setError(fmt.Sprintf("SlowDNS: %v", slowdnsErr))
		}
	}
}

func (t *XraySlowDNSTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}