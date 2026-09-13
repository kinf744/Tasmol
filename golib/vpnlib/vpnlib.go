// Package vpnlib is the gomobile entry point for the Android application
// (Voie B, no-root operation).
//
// Architecture: the Android VpnService captures device packets into a TUN
// file descriptor and hands it to Controller.Start. The data plane IS the
// official Xray binary (v26.5.9, stored in the repository bundle): vpnlib
// spawns it as a child process with the TUN fd inherited as fd 3
// (Go os/exec ExtraFiles) and XRAY_TUN_FD=3 in its environment, which the
// documented Xray TUN inbound reads on Android. Xray routes everything
// through the active tunnel's outbound and resolves DNS over HTTPS.
//
// Per active tunnel, the front Xray dials:
//   - ssh / ssh_slowdns : SOCKS5 outbound -> local native-SSH SOCKS
//     (10801 / 10802), dnstt+SSH processes driven by the core manager.
//   - xray              : native VLESS outbound straight to the server.
//   - xray_slowdns      : native VLESS outbound to the local dnstt forward
//     (127.0.0.1:2224), dnstt process driven by vpnlib.
//   - zivpn             : SOCKS5 outbound -> local zivpn client SOCKS
//     (10810), zivpn client process driven by the core manager.
//
// The app's own UID is excluded from the VPN via
// VpnService.Builder.addDisallowedApplication, so upstream sockets never
// loop back into the TUN.
//
// Only string/int/bool cross the gomobile boundary (JSON documents).
package vpnlib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"vpn-app/internal/api"
	"vpn-app/internal/config"
	"vpn-app/internal/core"
	"vpn-app/internal/tunnel"
)

// frontChildFd is the fd number the TUN fd is inherited as inside the
// Xray child process (Go os/exec ExtraFiles[0] always lands on fd 3).
// XRAY_TUN_FD is set to the same value.
const frontChildFd = "3"

// startParams configures Controller.Start (JSON document from Kotlin).
type startParams struct {
	ConfigPath   string            `json:"config_path"`
	BinDir       string            `json:"bin_dir"`
	BinNames     map[string]string `json:"bin_names"`
	NativeSSH    bool              `json:"native_ssh"`
	TunFd        int               `json:"tun_fd"`
	MTU          int               `json:"mtu"`
	ManagePort   int               `json:"manage_port"`
	ActiveTunnel string            `json:"active_tunnel"`
	AutoFollow   bool              `json:"auto_follow"`
}

// Controller owns the whole mobile VPN session.
type Controller struct {
	mu      sync.Mutex
	running bool

	cfgMgr *config.Manager
	vpn    *core.VPNCore
	apiSrv *api.Server

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	front      *exec.Cmd
	frontCfg   string
	frontAlive bool
	tunFd      int
	mtu        int
	configPath string
	dnsProcs   map[string]*dnsttProc
	activeID   string
	autoFollow bool
	startTime  time.Time
}

type dnsttProc struct {
	cmd     *exec.Cmd
	fwdPort int
}

// NewController creates a Controller. It must be called once.
func NewController() *Controller {
	return &Controller{dnsProcs: make(map[string]*dnsttProc)}
}

// MobileVersion returns the data-plane version.
func MobileVersion() string {
	return "2.0.0-xray"
}

func errJSON(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}

// Start boots the management core, the helpers of the active tunnel and the
// Xray front fed by the Android TUN fd. Returns "" on success or a JSON
// {"error": "..."} document.
func (c *Controller) Start(paramsJSON string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return ""
	}

	var p startParams
	if err := json.Unmarshal([]byte(paramsJSON), &p); err != nil {
		return errJSON(fmt.Errorf("invalid params: %w", err))
	}
	if p.ConfigPath == "" {
		return errJSON(fmt.Errorf("config_path is required"))
	}
	if p.TunFd <= 0 {
		return errJSON(fmt.Errorf("tun_fd is required"))
	}
	if p.MTU <= 0 {
		p.MTU = 1500
	}
	if err := os.MkdirAll(filepath.Dir(p.ConfigPath), 0755); err != nil {
		return errJSON(err)
	}

	// Wire tunnel engines: bundled official binaries + native SSH.
	tunnel.BinDir = p.BinDir
	tunnel.BinNames = p.BinNames
	tunnel.NativeSSH = p.NativeSSH

	cfgMgr, err := config.NewManager(p.ConfigPath)
	if err != nil {
		return errJSON(fmt.Errorf("config: %w", err))
	}

	vpn, err := core.NewVPNCoreWithOptions(cfgMgr, core.Options{EnableFeatures: false})
	if err != nil {
		cfgMgr.Close()
		return errJSON(fmt.Errorf("core: %w", err))
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.cfgMgr = cfgMgr
	c.vpn = vpn
	c.tunFd = p.TunFd
	c.mtu = p.MTU
	c.configPath = p.ConfigPath
	c.autoFollow = p.AutoFollow
	c.activeID = p.ActiveTunnel

	if c.activeID == "" {
		for _, tc := range cfgMgr.Get().Tunnels {
			if tc.Enabled {
				c.activeID = tc.ID
				break
			}
		}
	}
	if c.activeID == "" {
		c.cleanupLocked()
		return errJSON(fmt.Errorf("no tunnel configured: add one first"))
	}

	// Helpers (dnstt / ssh / zivpn processes) then the Xray front.
	if err := c.ensureHelpersLocked(c.activeID); err != nil {
		c.cleanupLocked()
		return errJSON(err)
	}
	if err := c.startFrontLocked(); err != nil {
		c.cleanupLocked()
		return errJSON(err)
	}

	// Embedded management Web UI (same UI as Termux/server mode).
	if p.ManagePort > 0 {
		c.apiSrv = api.NewServer(vpn, cfgMgr)
		addr := fmt.Sprintf("127.0.0.1:%d", p.ManagePort)
		go func() {
			_ = c.apiSrv.Run(addr)
		}()
	}

	c.startTime = time.Now()
	c.running = true

	if c.autoFollow {
		c.wg.Add(1)
		go c.followLoop()
	}

	return ""
}

// Stop tears the session down. Returns "" on success.
func (c *Controller) Stop() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return ""
	}
	c.cleanupLocked()
	return ""
}

func (c *Controller) cleanupLocked() {
	if c.cancel != nil {
		c.cancel()
	}
	c.killFrontLocked()
	for id, dp := range c.dnsProcs {
		if dp.cmd != nil && dp.cmd.Process != nil {
			_ = dp.cmd.Process.Kill()
		}
		delete(c.dnsProcs, id)
	}
	if c.vpn != nil {
		_ = c.vpn.Stop(context.Background())
		c.vpn = nil
	}
	if c.cfgMgr != nil {
		_ = c.cfgMgr.Close()
		c.cfgMgr = nil
	}
	c.apiSrv = nil
	c.running = false
	c.activeID = ""
	c.wg.Wait()
}

func (c *Controller) killFrontLocked() {
	if c.front != nil && c.front.Process != nil {
		_ = c.front.Process.Kill()
		_, _ = c.front.Process.Wait()
	}
	c.front = nil
	c.frontAlive = false
	if c.frontCfg != "" {
		os.Remove(c.frontCfg)
		c.frontCfg = ""
	}
}

// ensureHelpersLocked starts the helper processes the active tunnel needs.
// The front Xray instance itself carries xray-native outbounds, so manager
// processes for xray types are stopped to avoid duplicate binds.
func (c *Controller) ensureHelpersLocked(id string) error {
	t, ok := c.vpn.GetTunnelManager().Get(id)
	if !ok {
		return fmt.Errorf("tunnel not found: %s", id)
	}
	cfg := t.Config()

	switch cfg.Type {
	case config.TunnelXray:
		// Front carries the VLESS outbound: make sure no duplicate
		// manager process holds the local SOCKS port.
		_ = t.Stop(context.Background())
		return nil
	case config.TunnelXraySlowDNS:
		_ = t.Stop(context.Background())
		return c.ensureDnsttLocked(id, cfg, tunnel.DnsttForwardPort(cfg, tunnel.DefaultXraySlowDNSFwdPort))
	default:
		// ssh / ssh_slowdns / zivpn expose a local SOCKS5 used as the
		// front's upstream.
		if t.Status() != tunnel.StatusRunning {
			if err := t.Start(c.ctx); err != nil {
				return fmt.Errorf("start tunnel %s: %w", t.Name(), err)
			}
		}
		return nil
	}
}

// ensureDnsttLocked starts (once) the dnstt forward for tunnels whose
// outbound the front dials directly (xray_slowdns).
func (c *Controller) ensureDnsttLocked(id string, cfg *config.TunnelConfig, fwdPort int) error {
	if dp, ok := c.dnsProcs[id]; ok && dp.cmd != nil {
		return nil
	}
	cmd, err := tunnel.StartDnstt(c.ctx, cfg, fwdPort)
	if err != nil {
		return err
	}
	c.dnsProcs[id] = &dnsttProc{cmd: cmd, fwdPort: fwdPort}
	return nil
}

// frontOutbound builds the "proxy" outbound of the front Xray for tc.
func frontOutbound(tc *config.TunnelConfig) (map[string]interface{}, error) {
	switch tc.Type {
	case config.TunnelSSH, config.TunnelSSHSlowDNS, config.TunnelZivpn:
		return map[string]interface{}{
			"protocol": "socks",
			"tag":      "proxy",
			"settings": map[string]interface{}{
				"servers": []map[string]interface{}{
					{"address": "127.0.0.1", "port": tunnel.SocksPort(tc)},
				},
			},
		}, nil
	case config.TunnelXray:
		if tc.Auth.UUID == "" {
			return nil, fmt.Errorf("xray uuid is required (auth.uuid)")
		}
		port := tc.Server.Port
		if port == 0 {
			port = 443
		}
		return tunnel.BuildVlessOutbound(tc, tc.Server.Host, port), nil
	case config.TunnelXraySlowDNS:
		if tc.Auth.UUID == "" {
			return nil, fmt.Errorf("xray uuid is required (auth.uuid)")
		}
		fwd := tunnel.DnsttForwardPort(tc, tunnel.DefaultXraySlowDNSFwdPort)
		return tunnel.BuildVlessOutbound(tc, "127.0.0.1", fwd), nil
	default:
		return nil, fmt.Errorf("unsupported tunnel type: %s", tc.Type)
	}
}

// buildFrontConfig builds the front Xray JSON: TUN inbound fed by
// XRAY_TUN_FD, active-tunnel outbound, DNS over HTTPS, sane routing.
func buildFrontConfig(tc *config.TunnelConfig, mtu int) ([]byte, error) {
	proxy, err := frontOutbound(tc)
	if err != nil {
		return nil, err
	}

	doc := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "tun-in",
				"protocol": "tun",
				"settings": map[string]interface{}{
					"name": "tasvpn",
					"mtu":  mtu,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
				},
			},
		},
		"outbounds": []interface{}{
			proxy,
			map[string]interface{}{"protocol": "dns", "tag": "dns-out"},
			map[string]interface{}{"protocol": "freedom", "tag": "direct"},
			map[string]interface{}{"protocol": "blackhole", "tag": "block"},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []interface{}{
				map[string]interface{}{
					"type": "field", "port": "53", "outboundTag": "dns-out",
				},
				map[string]interface{}{
					"type": "field", "network": "tcp,udp", "outboundTag": "proxy",
				},
			},
		},
		"dns": map[string]interface{}{
			"servers":       []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
			"queryStrategy": "UseIP",
		},
	}

	return json.Marshal(doc)
}

// startFrontLocked writes the front config and spawns the official Xray
// binary with the TUN fd inherited as fd 3 (caller holds c.mu).
func (c *Controller) startFrontLocked() error {
	t, ok := c.vpn.GetTunnelManager().Get(c.activeID)
	if !ok {
		return fmt.Errorf("active tunnel gone: %s", c.activeID)
	}

	raw, err := buildFrontConfig(t.Config(), c.mtu)
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(filepath.Dir(c.configPath), "front.json")
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		return fmt.Errorf("write front config: %w", err)
	}

	tunFile := os.NewFile(uintptr(c.tunFd), "tun")
	if tunFile == nil {
		os.Remove(cfgPath)
		return fmt.Errorf("invalid tun fd %d", c.tunFd)
	}

	bin := tunnel.LookupBin(tunnel.BinDir, tunnel.BinXray)
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Env = append(os.Environ(),
		"XRAY_TUN_FD="+frontChildFd,
		"xray.tun.fd="+frontChildFd,
		"XRAY_LOCATION_ASSET="+tunnel.BinDir,
	)
	// ExtraFiles[0] is inherited by the child as fd 3.
	cmd.ExtraFiles = []*os.File{tunFile}

	if err := cmd.Start(); err != nil {
		os.Remove(cfgPath)
		return fmt.Errorf("xray front start: %w", err)
	}

	c.front = cmd
	c.frontCfg = cfgPath
	c.frontAlive = true
	go c.watchFront(cmd)

	// Brief grace period: a broken config kills the child immediately.
	time.Sleep(1500 * time.Millisecond)
	if !c.frontProcessAlive() {
		out := "xray front exited immediately (bad config or bad TUN fd?)"
		c.killFrontLocked()
		return fmt.Errorf("%s", out)
	}
	return nil
}

// frontProcessAlive reports whether the front child is still running.
func (c *Controller) frontProcessAlive() bool {
	if c.front == nil || c.front.Process == nil {
		return false
	}
	// Signal 0 performs error checking without delivering a signal.
	if err := c.front.Process.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	return true
}

// watchFront flips frontAlive off when the child exits.
func (c *Controller) watchFront(cmd *exec.Cmd) {
	_ = cmd.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.front == cmd {
		c.frontAlive = false
	}
}

// rebuildFrontLocked restarts the front (tunnel switch).
func (c *Controller) rebuildFrontLocked() error {
	c.killFrontLocked()
	return c.startFrontLocked()
}

// followLoop migrates the front to any running tunnel when the active one
// dies (client asked with auto_follow).
func (c *Controller) followLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			if !c.running {
				c.mu.Unlock()
				continue
			}
			activeAlive := c.frontAlive
			if t, ok := c.vpn.GetTunnelManager().Get(c.activeID); ok {
				cfgType := t.Config().Type
				if cfgType != config.TunnelXray && cfgType != config.TunnelXraySlowDNS {
					activeAlive = activeAlive && t.Status() == tunnel.StatusRunning
				}
			} else {
				activeAlive = false
			}
			if !activeAlive {
				for _, cand := range c.vpn.GetTunnelManager().List() {
					ccfg := cand.Config()
					usable := ccfg.Enabled && (cand.Status() == tunnel.StatusRunning ||
						ccfg.Type == config.TunnelXray || ccfg.Type == config.TunnelXraySlowDNS)
					if !usable {
						continue
					}
					c.activeID = cand.ID()
					if err := c.ensureHelpersLocked(c.activeID); err == nil {
						_ = c.rebuildFrontLocked()
					}
					break
				}
			}
			c.mu.Unlock()
		}
	}
}

// SetActiveTunnel switches the data plane to the tunnel: helpers are
// ensured, then the front is rebuilt around its outbound.
func (c *Controller) SetActiveTunnel(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	if _, ok := c.vpn.GetTunnelManager().Get(id); !ok {
		return errJSON(fmt.Errorf("tunnel not found: %s", id))
	}
	if err := c.ensureHelpersLocked(id); err != nil {
		return errJSON(err)
	}
	c.activeID = id
	if err := c.rebuildFrontLocked(); err != nil {
		return errJSON(err)
	}
	return ""
}

// StartTunnel starts a tunnel helper process without touching the front.
func (c *Controller) StartTunnel(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	t, ok := c.vpn.GetTunnelManager().Get(id)
	if !ok {
		return errJSON(fmt.Errorf("tunnel not found: %s", id))
	}
	if t.Status() != tunnel.StatusRunning {
		if err := t.Start(c.ctx); err != nil {
			return errJSON(fmt.Errorf("start tunnel %s: %w", t.Name(), err))
		}
	}
	return ""
}

// StopTunnel stops a tunnel helper process.
func (c *Controller) StopTunnel(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	t, ok := c.vpn.GetTunnelManager().Get(id)
	if !ok {
		return errJSON(fmt.Errorf("tunnel not found: %s", id))
	}
	if err := t.Stop(context.Background()); err != nil {
		return errJSON(err)
	}
	return ""
}

// AddTunnel creates a tunnel from a TunnelConfig JSON document.
func (c *Controller) AddTunnel(tunnelJSON string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	var tc config.TunnelConfig
	if err := json.Unmarshal([]byte(tunnelJSON), &tc); err != nil {
		return errJSON(fmt.Errorf("invalid tunnel: %w", err))
	}
	if err := c.cfgMgr.AddTunnel(&tc); err != nil {
		return errJSON(err)
	}
	t, err := tunnel.CreateTunnel(&tc)
	if err != nil {
		return errJSON(err)
	}
	if err := c.vpn.GetTunnelManager().Add(t); err != nil {
		return errJSON(err)
	}
	b, _ := json.Marshal(map[string]string{"id": tc.ID})
	return string(b)
}

// UpdateTunnel replaces a tunnel config (restarts helpers/front if active).
func (c *Controller) UpdateTunnel(id, tunnelJSON string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	var tc config.TunnelConfig
	if err := json.Unmarshal([]byte(tunnelJSON), &tc); err != nil {
		return errJSON(fmt.Errorf("invalid tunnel: %w", err))
	}
	tc.ID = id

	wasActive := c.activeID == id
	if old, ok := c.vpn.GetTunnelManager().Get(id); ok {
		_ = old.Stop(context.Background())
		_ = c.vpn.GetTunnelManager().Remove(id)
	}
	if err := c.cfgMgr.UpdateTunnel(id, tc); err != nil {
		return errJSON(err)
	}
	t, err := tunnel.CreateTunnel(&tc)
	if err != nil {
		return errJSON(err)
	}
	if err := c.vpn.GetTunnelManager().Add(t); err != nil {
		return errJSON(err)
	}
	if wasActive {
		if err := c.ensureHelpersLocked(id); err != nil {
			return errJSON(err)
		}
		if err := c.rebuildFrontLocked(); err != nil {
			return errJSON(err)
		}
	}
	return ""
}

// DeleteTunnel removes a tunnel (refused while it carries the front).
func (c *Controller) DeleteTunnel(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	if c.activeID == id {
		return errJSON(fmt.Errorf("cannot delete the active tunnel: disconnect first"))
	}
	if err := c.vpn.GetTunnelManager().Remove(id); err != nil {
		return errJSON(err)
	}
	if err := c.cfgMgr.DeleteTunnel(id); err != nil {
		return errJSON(err)
	}
	return ""
}

// ImportConfig replaces the whole configuration (YAML or JSON). The service
// must be restarted afterwards for new tunnels to load.
func (c *Controller) ImportConfig(content string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	trimmed := content
	for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\n' || trimmed[0] == '\t' || trimmed[0] == '\r') {
		trimmed = trimmed[1:]
	}
	var err error
	if len(trimmed) > 0 && trimmed[0] == '{' {
		err = c.cfgMgr.ImportJSON([]byte(content))
	} else {
		err = c.cfgMgr.ImportYAML([]byte(content))
	}
	if err != nil {
		return errJSON(err)
	}
	b, _ := json.Marshal(map[string]bool{"restart_required": true})
	return string(b)
}

// ExportConfig returns the whole configuration as YAML.
func (c *Controller) ExportConfig() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	data, err := c.cfgMgr.Export()
	if err != nil {
		return errJSON(err)
	}
	out, err := yaml.Marshal(data)
	if err != nil {
		return errJSON(err)
	}
	return string(out)
}

// GetStatus returns the session status as JSON.
func (c *Controller) GetStatus() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	type tunStatus struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Status  string `json:"status"`
		Enabled bool   `json:"enabled"`
		Uptime  int64  `json:"uptime"`
		Error   string `json:"error,omitempty"`
		Socks   string `json:"socks"`
	}

	out := map[string]interface{}{"running": c.running}
	if !c.running || c.vpn == nil {
		b, _ := json.Marshal(out)
		return string(b)
	}

	var list []tunStatus
	for _, t := range c.vpn.GetTunnelManager().List() {
		st := t.Stats()
		list = append(list, tunStatus{
			ID:      t.ID(),
			Name:    t.Name(),
			Type:    string(t.Type()),
			Status:  string(t.Status()),
			Enabled: t.Config().Enabled,
			Uptime:  st.Uptime,
			Error:   st.LastError,
			Socks:   tunnel.SocksAddr(t.Config()),
		})
	}
	out["active_tunnel"] = c.activeID
	out["front_running"] = c.frontAlive
	out["uptime"] = int64(time.Since(c.startTime).Seconds())
	out["tunnels"] = list

	b, _ := json.Marshal(out)
	return string(b)
}

func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s", addr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
