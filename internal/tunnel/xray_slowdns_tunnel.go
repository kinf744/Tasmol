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
	shimCmd     *exec.Cmd
	cancel      context.CancelFunc
	startTime   time.Time
	configPath  string
	shimDir     string
	pickedSocks int
	pickedFwd   int
	pickedShim  int
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

// shimPort renvoie le port du shim WG (UDP → VLESS TCP) pour les profils
// WireGuard. 0 = shim non démarré (profil non-WG).
func (t *XraySlowDNSTunnel) shimPort() int { return t.pickedShim }

// generateXrayConfig builds an Xray config whose outbound dials the local
// dnstt forward (127.0.0.1:fwdPort) instead of the remote server directly.
// Pour un profil WireGuard, l'endpoint WG devient le shim local
// (127.0.0.1:shimPort) : le WG envoie ses paquets UDP vers le shim, qui les
// encapsule via VLESS-UDP dans le forward dnstt TCP (cf. BuildWGShimConfig).
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

	cfg := t.config
	if IsWireGuard(t.config) && t.shimPort() > 0 {
		clone := *t.config
		adv := make(map[string]interface{}, len(t.config.Advanced)+1)
		for k, v := range t.config.Advanced {
			adv[k] = v
		}
		adv["wg_peer_endpoint"] = fmt.Sprintf("127.0.0.1:%d", t.shimPort())
		clone.Advanced = adv
		cfg = &clone
	}
	outbound := SlowDNSOutbound(cfg, t.fwdPort())

	strategy := t.config.Routing.DomainStrategy
	if strategy == "" {
		// UseIP: resolve through the internal DNS client, the Android
		// system resolver is unusable from the xray child ([::1]:53).
		strategy = "UseIP"
	}
	dnsCfg := t.config.Routing.DNS
	if len(dnsCfg.Servers) == 0 && len(dnsCfg.Hosts) == 0 {
		dnsCfg.Servers = XrayDNSServers()
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

// BuildWGShimConfig builds the Xray config that bridges WireGuard UDP into
// the dnstt TCP forward: a dokodemo-door UDP inbound (fixed target = the
// WireGuard server port on the server loopback, i.e. cfg.Server.Port)
// feeding a VLESS outbound pointed at the local dnstt forward. Server side,
// the VLESS backend relays UDP to 127.0.0.1:<wgPort> (wg0).
func BuildWGShimConfig(uuid string, fwdPort, shimPort, wgServerPort int) (string, error) {
	cfg := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []interface{}{
			map[string]interface{}{
				"listen":   "127.0.0.1",
				"port":     shimPort,
				"protocol": "dokodemo-door",
				"tag":      "wgshim-in",
				"settings": map[string]interface{}{
					"address":       "127.0.0.1",
					"port":          wgServerPort,
					"network":       "udp",
					"followRedirect": false,
				},
			},
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": "127.0.0.1",
							"port":    fwdPort,
							"users": []interface{}{
								map[string]interface{}{
									"id":         uuid,
									"encryption": "none",
									"level":      0,
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{"network": "tcp", "security": "none"},
			},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// startWGShim lance le processus Xray shim (bridge WG UDP -> VLESS -> dnstt
// TCP). Le wg_server_port est le port d'écoute de wg0 sur le SERVEUR
// (cfg.Server.Port, ex. 443) vu depuis son loopback car le relais VLESS
// côté serveur tourne sur la même machine.
func (t *XraySlowDNSTunnel) startWGShim(ctx context.Context, shimPort int) (*exec.Cmd, string, error) {
	content, err := BuildWGShimConfig(t.config.Auth.UUID, t.fwdPort(), shimPort, t.config.Server.Port)
	if err != nil {
		return nil, "", err
	}
	tmpDir, err := os.MkdirTemp(TmpDir, "xray-wgshim-*")
	if err != nil {
		return nil, "", err
	}
	confPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(confPath, []byte(content), 0600); err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}
	cmd := exec.CommandContext(ctx, LookupBin(BinDir, BinXray), "run", "-config", confPath)
	cmd.Env = append(os.Environ(), androidCAEnv()...)
	if BinDir != "" {
		cmd.Env = append(cmd.Env, "XRAY_LOCATION_ASSET="+BinDir)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}
	Tracef("[xray-slowdns] WG shim started pid=%d udp=127.0.0.1:%d -> vless->fwd:%d -> server_udp:%d",
		cmd.Process.Pid, shimPort, t.fwdPort(), t.config.Server.Port)
	go PipeLinesToLog(stdout, "[xray-slowdns][shim][out]")
	go PipeLinesToLog(stderr, "[xray-slowdns][shim][err]")
	return cmd, tmpDir, nil
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
	Tracef("[xray-slowdns] phase 1/2: dnstt forward :%d", t.fwdPort())
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

	// Profils WireGuard : pont UDP→TCP — le serveur WG n'atteint pas le
	// réseau de l'opérateur en UDP direct, donc les paquets WG sont relayés
	// via VLESS-UDP à travers le forward dnstt (cf. balancer : le front RR
	// pointe vers le SOCKS du membre pour ces profils).
	if IsWireGuard(t.config) {
		if t.config.Auth.UUID == "" {
			Errorf("xray-slowdns", "wg shim: uuid manquant (bridge VLESS)")
			t.slowdnscmd.Process.Kill()
			t.status = StatusError
			t.setError("uuid requis pour le pont WG (auth.uuid)")
			return fmt.Errorf("wg slowdns bridge requires auth.uuid")
		}
		t.pickedShim = 0
		shPort, perr := pickFreePort()
		if perr != nil {
			Errorf("xray-slowdns", "wg shim port: %v", perr)
			t.slowdnscmd.Process.Kill()
			t.status = StatusError
			t.setError(perr.Error())
			return perr
		}
		shimCmd, shimDir, serr := t.startWGShim(ctx, shPort)
		if serr != nil {
			Errorf("xray-slowdns", "wg shim: %v", serr)
			t.slowdnscmd.Process.Kill()
			t.status = StatusError
			t.setError(serr.Error())
			return serr
		}
		t.shimCmd = shimCmd
		t.shimDir = shimDir
		t.pickedShim = shPort
		go t.watchShim(t.shimCmd)
	}

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

	Tracef("[xray-slowdns] phase 2/2: starting xray")
	t.xrayCmd = exec.CommandContext(ctx, LookupBin(BinDir, BinXray), "run", "-config", t.configPath)
	t.xrayCmd.Env = append(os.Environ(), androidCAEnv()...)
	if BinDir != "" {
		t.xrayCmd.Env = append(t.xrayCmd.Env, "XRAY_LOCATION_ASSET="+BinDir)
	}
	Tracef("[xray-slowdns] binary=%q configBytes=%d", t.xrayCmd.Path, len(configContent))
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
	Tracef("[xray-slowdns] SOCKS ready, RUNNING name=%q", t.config.Name)

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

	if t.shimCmd != nil && t.shimCmd.Process != nil {
		t.shimCmd.Process.Kill()
		t.shimCmd.Wait()
		Tracef("[xray-slowdns] wg shim reaped")
	}
	if t.shimDir != "" {
		os.RemoveAll(t.shimDir)
		t.shimDir = ""
	}

	if t.configPath != "" {
		os.Remove(t.configPath)
		os.Remove(filepath.Dir(t.configPath))
	}

	t.pickedSocks = 0
	t.pickedFwd = 0
	t.pickedShim = 0
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

// watchShim : si le shim WG meurt alors que la session tourne, on marque le
// tunnel en erreur (sans lui, l'endpoint WG 127.0.0.1:shim n'a plus de taker).
func (t *XraySlowDNSTunnel) watchShim(cmd *exec.Cmd) {
	err := cmd.Wait()
	Tracef("[xray-slowdns] wg shim exited: %v", err)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusRunning {
		t.status = StatusError
		if err != nil {
			t.setError(fmt.Sprintf("WG shim: %v", err))
		} else {
			t.setError("WG shim exited")
		}
	}
}
