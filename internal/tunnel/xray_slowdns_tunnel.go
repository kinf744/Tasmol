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
// v25.12.8:
//
//	slowdns -udp <resolver>:53 -pubkey <hex> <ns-domain> 127.0.0.1:<fwdPort>
//	xray run -config <generated>   (outbound -> 127.0.0.1:<fwdPort>)
//
// Xray exposes a local SOCKS5 inbound (default 127.0.0.1:10809) used as the
// device upstream. Defaults: fwdPort 2224, socksPort 10809, resolver
// 8.8.8.8. All overridable via the tunnel Advanced map ("fwd_port",
// "socks_port", "dns_resolver").
type XraySlowDNSTunnel struct {
	mu         sync.RWMutex
	config     *config.TunnelConfig
	status     Status
	stats      Stats
	xrayCmd    *exec.Cmd
	slowdnscmd *exec.Cmd
	cancel     context.CancelFunc
	startTime  time.Time
	configPath string
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
	return advInt(t.config.Advanced, "fwd_port", 2224)
}

func (t *XraySlowDNSTunnel) socksPort() int {
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

// buildSlowDNSArgs builds the official dnstt-client invocation:
// slowdns -udp <resolver>:53 -pubkey <hex> <ns-domain> 127.0.0.1:<fwdPort>
func (t *XraySlowDNSTunnel) buildSlowDNSArgs() []string {
	return []string{
		"-udp", t.resolver() + ":53",
		"-pubkey", t.config.Server.PublicKey,
		t.nsDomain(),
		fmt.Sprintf("127.0.0.1:%d", t.fwdPort()),
	}
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

	streamSettings := map[string]interface{}{
		"network":  t.config.Transport.Network,
		"security": t.config.Transport.Security,
	}

	if t.config.Transport.Network == "ws" {
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": t.config.Transport.Path,
			"headers": map[string]string{
				"Host": t.config.Transport.Host,
			},
		}
	}

	if t.config.Transport.Security == "tls" {
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    t.config.Server.SNI,
			"allowInsecure": false,
			"fingerprint":   t.config.Transport.Fingerprint,
			"alpn":          t.config.Transport.ALPN,
		}
	}

	if t.config.Transport.Security == "reality" {
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  t.config.Server.SNI,
			"publicKey":   t.config.Server.PublicKey,
			"shortId":     t.config.Server.ShortID,
			"fingerprint": t.config.Transport.Fingerprint,
		}
	}

	settings := map[string]interface{}{
		"vnext": []map[string]interface{}{
			{
				"address": "127.0.0.1",
				"port":    t.fwdPort(),
				"users": []map[string]interface{}{
					{
						"id":         t.config.Auth.UUID,
						"flow":       t.config.Auth.Flow,
						"encryption": "none",
					},
				},
			},
		},
	}

	outbound := map[string]interface{}{
		"protocol":       "vless",
		"tag":            "proxy",
		"settings":       settings,
		"streamSettings": streamSettings,
	}

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

func (t *XraySlowDNSTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}

	if t.nsDomain() == "" {
		return fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if t.config.Server.PublicKey == "" {
		return fmt.Errorf("slowdns server public key is required (server.public_key)")
	}
	if t.config.Auth.UUID == "" {
		return fmt.Errorf("xray uuid is required (auth.uuid)")
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	slowdnsArgs := t.buildSlowDNSArgs()
	t.slowdnscmd = exec.CommandContext(ctx, LookupBin(BinDir, BinSlowDNS), slowdnsArgs...)
	if err := t.slowdnscmd.Start(); err != nil {
		t.status = StatusError
		t.setError(fmt.Sprintf("SlowDNS start failed: %v", err))
		return fmt.Errorf("failed to start SlowDNS (dnstt-client): %w", err)
	}

	// Wait until dnstt exposes the forwarded port before starting Xray.
	t.mu.Unlock()
	fwdErr := waitForTCP(fmt.Sprintf("127.0.0.1:%d", t.fwdPort()), 20*time.Second)
	t.mu.Lock()

	if fwdErr != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("SlowDNS forward not ready: %v", fwdErr))
		return fmt.Errorf("slowdns forward not ready: %w", fwdErr)
	}

	configContent, err := t.generateXrayConfig()
	if err != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	tmpDir, err := os.MkdirTemp("", "xray-slowdns-*")
	if err != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.configPath = filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(t.configPath, []byte(configContent), 0644); err != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	t.xrayCmd = exec.CommandContext(ctx, LookupBin(BinDir, BinXray), "run", "-config", t.configPath)
	if BinDir != "" {
		t.xrayCmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+BinDir)
	}
	if err := t.xrayCmd.Start(); err != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("Xray start failed: %v", err))
		return fmt.Errorf("failed to start Xray: %w", err)
	}

	// Wait until the local SOCKS5 is exposed before reporting running.
	t.mu.Unlock()
	socksErr := waitForTCP(fmt.Sprintf("127.0.0.1:%d", t.socksPort()), 20*time.Second)
	t.mu.Lock()

	if socksErr != nil {
		t.xrayCmd.Process.Kill()
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("Xray SOCKS not ready: %v", socksErr))
		return fmt.Errorf("xray socks not ready: %w", socksErr)
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
