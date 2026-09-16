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

// XraySlowDNSTunnel chains the official dnstt SlowDNS client with Xray
// v26.5.9 (Termux/server mode; the mobile front embeds xray-core):
//
//	slowdns -udp <resolver>:53 -pubkey <hex> <ns-domain> 127.0.0.1:<fwdPort>
//	xray run -config <generated>   (outbound -> 127.0.0.1:<fwdPort>)
//
// Xray exposes a local SOCKS5 inbound (default 127.0.0.1:10809) used as the
// device upstream. Defaults: fwdPort 2224, socksPort 10809, resolver
// 8.8.8.8. All overridable via the tunnel Advanced map ("fwd_port",
// "socks_port", "dns_resolver").
type XraySlowDNSTunnel struct {
	mu          sync.RWMutex
	config      *config.TunnelConfig
	status      Status
	stats       Stats
	xrayCmd     *exec.Cmd
	slowdnscmd  *exec.Cmd
	cancel      context.CancelFunc
	startTime   time.Time
	configPath  string
	pickedSocks int
	pickedFwd   int
}

func NewXraySlowDNSTunnel(cfg *config.TunnelConfig) *XraySlowDNSTunnel {
	return &XraySlowDNSTunnel{
		config: cfg,
		status: StatusStopped,
		stats:  Stats{},
	}
}

func (t *XraySlowDNSTunnel) ID() string              { return t.config.ID }
func (t *XraySlowDNSTunnel) Name() string            { return t.config.Name }
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

func (t *XraySlowDNSTunnel) fwdPort() int {
	if t.pickedFwd > 0 {
		return t.pickedFwd
	}
	return advInt(t.config.Advanced, "fwd_port", 2224)
}

func (t *XraySlowDNSTunnel) socksPort() int {
	if t.pickedSocks > 0 {
		return t.pickedSocks
	}
	return advInt(t.config.Advanced, "socks_port", 10809)
}

func (t *XraySlowDNSTunnel) resolver() string {
	if t.config.Server.DNSResolver != "" {
		return t.config.Server.DNSResolver
	}
	return advStr(t.config.Advanced, "dns_resolver", "8.8.8.8")
}

func (t *XraySlowDNSTunnel) nsDomain() string {
	if t.config.Server.Nameserver != "" {
		return t.config.Server.Nameserver
	}
	return t.config.Server.Hostname
}

// generateXrayConfig builds an Xray config whose outbound dials the local
// dnstt forward (127.0.0.1:fwdPort) instead of the remote server directly.
func (t *XraySlowDNSTunnel) generateXrayConfig() (string, error) {
	inbound := map[string]interface{}{
		"port":     t.socksPort(),
		"listen":   "127.0.0.1",
		"protocol": "socks",
		"settings": map[string]interface{}{
			"udp":  true,
			"auth": "noauth",
		},
	}

	outbound := SlowDNSOutbound(t.config, t.fwdPort())

	strategy := t.config.Routing.DomainStrategy
	if strategy == "" {
		// UseIP: resolve through the internal DNS client, the Android
		// system resolver is unusable from the xray child ([::1]:53).
		strategy = "UseIP"
	}
	dnsCfg := t.config.Routing.DNS
	if len(dnsCfg.Servers) == 0 && len(dnsCfg.Hosts) == 0 {
		dnsCfg.Servers = []string{"1.1.1.1", "8.8.8.8"}
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
		"dns": dnsCfg,
	}

	data, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (t *XraySlowDNSTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	Tracef("[xray-slowdns] Start() begin status=%s name=%q id=%s", t.status, t.config.Name, t.config.ID)

	if t.status == StatusRunning {
		Tracef("[xray-slowdns] already running, skip")
		return nil
	}

	Journalf("xray-slowdns", "slowdns ns=%q uuid=%v key=%d chars",
		t.nsDomain(), t.config.Auth.UUID != "", len(cleanDnsttKey(DnsttPubKey(t.config))))
	if t.nsDomain() == "" {
		Errorf("xray-slowdns", "nameserver domain empty")
		return fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if DnsttPubKey(t.config) == "" {
		Errorf("xray-slowdns", "slowdns public key empty")
		return fmt.Errorf("slowdns server public key is required (server.public_key or advanced.slowdns_pubkey)")
	}
	if t.config.Auth.UUID == "" && !HasOutboundJSON(t.config) {
		Errorf("xray-slowdns", "no uuid and no outbound_json")
		return fmt.Errorf("xray uuid is required (auth.uuid) or paste a link/JSON")
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	// Fresh random forward + SOCKS ports per session (overrides
	// respected). Clear stale entries first so nothing dials a dead port.
	ClearLiveForward(t.config.ID)
	ClearLiveSocksAddr(t.config.ID)
	fwd, err := PickLiveForward(t.config, DefaultXraySlowDNSFwdPort)
	if err != nil {
		Errorf("xray-slowdns", "fwd port: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.pickedFwd = fwd
	_, socksPort, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Errorf("xray-slowdns", "socks port: %v", err)
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.pickedSocks = socksPort
	Tracef("[xray-slowdns] picked fwd=:%d socks=127.0.0.1:%d", fwd, socksPort)

	// dnstt first: Xray dials the local forward once it answers.
	Journalf("xray-slowdns", "phase 1/2: dnstt forward :%d", t.fwdPort())
	t.mu.Unlock()
	dnsttCmd, err := StartDnstt(ctx, t.config, t.fwdPort())
	t.mu.Lock()

	if err != nil {
		Errorf("xray-slowdns", "dnstt phase: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.slowdnscmd = dnsttCmd

	configContent, err := t.generateXrayConfig()
	if err != nil {
		Errorf("xray-slowdns", "generateConfig: %v", err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	tmpDir, err := os.MkdirTemp(TmpDir, "xray-slowdns-*")
	if err != nil {
		Errorf("xray-slowdns", "mktemp in %s: %v", TmpDir, err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	if err != nil {
		Errorf("xray-slowdns", "mktemp: %v", err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.configPath = filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(t.configPath, []byte(configContent), 0644); err != nil {
		Errorf("xray-slowdns", "write config: %v", err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	Journalf("xray-slowdns", "phase 2/2: starting xray")
	t.xrayCmd = exec.CommandContext(ctx, LookupBin(BinDir, BinXray), "run", "-config", t.configPath)
	if BinDir != "" {
		t.xrayCmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+BinDir)
	}
	Tracef("[xray-slowdns] binary=%q config=%s", t.xrayCmd.Path, configContent)
	stdout, err := t.xrayCmd.StdoutPipe()
	if err != nil {
		Errorf("xray-slowdns", "stdout pipe: %v", err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	stderr, err := t.xrayCmd.StderrPipe()
	if err != nil {
		Errorf("xray-slowdns", "stderr pipe: %v", err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	if err := t.xrayCmd.Start(); err != nil {
		Errorf("xray-slowdns", "process start: %v", err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("Xray start failed: %v", err))
		return fmt.Errorf("failed to start Xray: %w", err)
	}
	Tracef("[xray-slowdns] process started pid=%d", t.xrayCmd.Process.Pid)
	go PipeLinesToLog(stdout, "[xray-slowdns][out]")
	go PipeLinesToLog(stderr, "[xray-slowdns][err]")

	// Wait until the local SOCKS5 is exposed before reporting running.
	Tracef("[xray-slowdns] waiting for SOCKS 127.0.0.1:%d ...", t.socksPort())
	t.mu.Unlock()
	socksErr := waitForTCPctx(ctx, fmt.Sprintf("127.0.0.1:%d", t.socksPort()), 20*time.Second)
	t.mu.Lock()

	if socksErr != nil {
		Errorf("xray-slowdns", "SOCKS not ready: %v", socksErr)
		t.xrayCmd.Process.Kill()
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("Xray SOCKS not ready: %v", socksErr))
		return fmt.Errorf("xray socks not ready: %w", socksErr)
	}
	Connf("xray-slowdns", "SOCKS ready, RUNNING name=%q", t.config.Name)

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

	Tracef("[xray-slowdns] Stop() name=%q", t.config.Name)
	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.xrayCmd != nil && t.xrayCmd.Process != nil {
		t.xrayCmd.Process.Kill()
		t.xrayCmd.Wait()
		Tracef("[xray-slowdns] xray reaped")
	}

	if t.slowdnscmd != nil && t.slowdnscmd.Process != nil {
		t.slowdnscmd.Process.Kill()
		t.slowdnscmd.Wait()
		Tracef("[xray-slowdns] slowdns reaped")
	}

	if t.configPath != "" {
		os.Remove(t.configPath)
		os.Remove(filepath.Dir(t.configPath))
	}

	t.pickedSocks = 0
	t.pickedFwd = 0
	ClearLiveForward(t.config.ID)
	ClearLiveSocksAddr(t.config.ID)
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
	xrayDone := make(chan error, 1)
	dnsDone := make(chan error, 1)
	go func() { xrayDone <- t.xrayCmd.Wait() }()
	go func() { dnsDone <- t.slowdnscmd.Wait() }()

	var xrayErr, slowdnsErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-xrayDone:
			xrayErr = err
			Tracef("[xray-slowdns] xray exited: %v", err)
		case err := <-dnsDone:
			slowdnsErr = err
			Tracef("[xray-slowdns] slowdns exited: %v", err)
		}
		if t.Status() != StatusRunning {
			return
		}
	}
	Tracef("[xray-slowdns] exited xray=%v slowdns=%v", xrayErr, slowdnsErr)

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
