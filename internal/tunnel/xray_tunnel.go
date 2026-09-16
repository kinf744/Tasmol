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
	socksPort  int
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
		"port":     t.socksPort,
		"listen":   "127.0.0.1",
		"protocol": "socks",
		"settings": map[string]interface{}{
			"udp":  true,
			"auth": "noauth",
		},
	}

	outbound := TunnelOutbound(t.config, t.config.Server.Host, t.config.Server.Port)

	// domainStrategy UseIP: Xray resolves outbound domains through its
	// internal DNS client (1.1.1.1/8.8.8.8, direct since our UID is
	// excluded from the VPN) instead of the system resolver, which is
	// dead on Android ([::1]:53 refused) and breaks every domain dial.
	strategy := t.config.Routing.DomainStrategy
	if strategy == "" {
		strategy = "UseIP"
	}

	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds":  []interface{}{inbound},
		"outbounds": []interface{}{outbound},
		"routing": map[string]interface{}{
			"domainStrategy": strategy,
			"rules":          t.config.Routing.Rules,
		},
		"dns": map[string]interface{}{
			"servers": []string{"1.1.1.1", "8.8.8.8"},
		},
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
	addr = resolveDialAddr(cfg, addr)
	streamSettings := buildStreamSettings(cfg, addr)

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

	Tracef("[xray] Start() begin status=%s name=%q id=%s", t.status, t.config.Name, t.config.ID)

	if t.status == StatusRunning {
		Tracef("[xray] already running, skip")
		return nil
	}

	hasUUID := t.config.Auth.UUID != ""
	hasJSON := HasOutboundJSON(t.config)
	Tracef("[xray] inputs uuidSet=%v outboundJSON=%v host=%q port=%d",
		hasUUID, hasJSON, t.config.Server.Host, t.config.Server.Port)
	if t.config.Auth.UUID == "" && !hasJSON {
		Errorf("xray", "no uuid and no outbound_json")
		return fmt.Errorf("xray needs a subscription link or JSON config (or manual uuid)")
	}
	if t.config.Server.Host == "" && !hasJSON {
		Errorf("xray", "server host empty")
		return fmt.Errorf("xray server host is required (server.host)")
	}

	t.status = StatusStarting
	t.setError("")

	// Fresh random SOCKS port per session (override respected): the old
	// hardcoded 10808 also mismatched custom socks_port overrides.
	ClearLiveSocksAddr(t.config.ID)
	_, socksPort, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Errorf("xray", "socks port: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.socksPort = socksPort
	Tracef("[xray] SOCKS picked 127.0.0.1:%d", socksPort)

	configContent, err := t.generateConfig()
	if err != nil {
		Errorf("xray", "generateConfig: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	tmpDir, err := os.MkdirTemp(TmpDir, "xray-*")
	if err != nil {
		Errorf("xray", "mktemp in %s: %v", TmpDir, err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.configPath = filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(t.configPath, []byte(configContent), 0644); err != nil {
		Errorf("xray", "write config: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	Tracef("[xray] config written to %s", t.configPath)

	ctx, t.cancel = context.WithCancel(ctx)
	Tracef("[xray] BinDir=%q BinNames=%v", BinDir, BinNames)
	bin := LookupBin(BinDir, BinXray)
	Tracef("[xray] resolved binary=%q", bin)
	t.cmd = exec.CommandContext(ctx, bin, "run", "-config", t.configPath)
	if BinDir != "" {
		t.cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+BinDir)
	}
	Tracef("[xray] binary=%q config=%s", t.cmd.Path, configContent)

	stdout, err := t.cmd.StdoutPipe()
	if err != nil {
		Errorf("xray", "stdout pipe: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	stderr, err := t.cmd.StderrPipe()
	if err != nil {
		Errorf("xray", "stderr pipe: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	if err := t.cmd.Start(); err != nil {
		Errorf("xray", "process start: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("failed to start Xray: %w", err)
	}
	Tracef("[xray] process started pid=%d", t.cmd.Process.Pid)
	go PipeLinesToLog(stdout, "[xray][out]")
	go PipeLinesToLog(stderr, "[xray][err]")

	// Wait until the local SOCKS inbound answers instead of assuming ready.
	socksAddr := fmt.Sprintf("127.0.0.1:%d", t.socksPort)
	Tracef("[xray] waiting for SOCKS %s ...", socksAddr)
	t.mu.Unlock()
	readyErr := waitForTCPctx(ctx, socksAddr, 15*time.Second)
	t.mu.Lock()
	if readyErr != nil {
		Errorf("xray", "SOCKS %s not ready: %v", socksAddr, readyErr)
		if t.cmd.Process != nil {
			t.cmd.Process.Kill()
		}
		t.status = StatusError
		t.setError(fmt.Sprintf("xray SOCKS not ready: %v", readyErr))
		return fmt.Errorf("xray socks not ready: %w", readyErr)
	}
	Tracef("[xray] SOCKS %s ready", socksAddr)

	t.startTime = time.Now()
	t.status = StatusRunning
	Connf("xray", "RUNNING name=%q", t.config.Name)

	go t.monitorProcess()

	return nil
}

func (t *XrayTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}

	Tracef("[xray] Stop() name=%q", t.config.Name)
	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
		Tracef("[xray] process reaped")
	}

	if t.configPath != "" {
		os.Remove(t.configPath)
		os.Remove(filepath.Dir(t.configPath))
		Tracef("[xray] temp config removed")
	}

	t.socksPort = 0
	ClearLiveSocksAddr(t.config.ID)
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
	Tracef("[xray] process exited: %v", err)
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
