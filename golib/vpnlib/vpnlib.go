// Package vpnlib is the gomobile entry point for the Android application
// (Voie B, no-root operation).
//
// Architecture: the Android VpnService captures device packets into a TUN
// file descriptor and hands it to Controller.Start. The data plane is an
// in-process userspace IP stack (gVisor via xjasonlyu/tun2socks) reading
// the fd directly: it forwards TCP through the local SOCKS5 proxy exposed
// by the active tunnel (native SSH / dnstt+SSH / local Xray / dnstt+Xray /
// uz_core balancer), relays UDP DNS (port 53) as DNS-over-TCP through the
// same SOCKS proxy (works with every tunnel type, including SSH which has
// no UDP support), and sends other UDP via SOCKS5 UDP ASSOCIATE.
//
// NOTE: the official Xray *binary* cannot serve as the front-end here: its
// linux build opens /dev/net/tun itself (permission denied in the app
// sandbox) and only GOOS=android builds honor XRAY_TUN_FD — which Xray does
// not publish for 32-bit ARM. Hence the in-process stack.
//
// The app's own UID is excluded from the VPN via
// VpnService.Builder.addDisallowedApplication, so upstream sockets never
// loop back into the TUN.
//
// Only string/int/bool cross the gomobile boundary (JSON documents).
package vpnlib

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	t2core "github.com/xjasonlyu/tun2socks/v2/core"
	t2device "github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	t2meta "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2proxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	t2tunnel "github.com/xjasonlyu/tun2socks/v2/tunnel"
	t2stat "github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"

	"vpn-app/internal/api"
	"vpn-app/internal/config"
	"vpn-app/internal/core"
	"vpn-app/internal/tunnel"
)

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
	// LogDir is the device Download directory; a real-time activity file
	// "kighmu.txt" is written there for diagnostics.
	LogDir string `json:"log_dir"`
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

	dev    t2device.Device
	stack  *stack.Stack
	tun    *t2tunnel.Tunnel
	dialer *swapDialer

	tunFd      int
	mtu        int
	configPath string
	activeID   string
	autoFollow bool
	startTime  time.Time
	logFile    *os.File
}

// NewController creates a Controller. It must be called once.
func NewController() *Controller {
	return &Controller{}
}

// MobileVersion returns the data-plane version.
func MobileVersion() string {
	return "2.1.0-tun2socks"
}

func errJSON(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}

// makeFileLogger returns a tunnel.LogFunc writing timestamped lines to
// <logDir>/kighmu.txt (created/truncated on each Start). Returns nil if
// logDir is empty or unwritable, so logging is always safe.
func (c *Controller) makeFileLogger(logDir string) func(string, ...interface{}) {
	if logDir == "" {
		return nil
	}
	path := filepath.Join(logDir, "kighmu.txt")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil
	}
	c.logFile = f
	var mu sync.Mutex
	return func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(f, "%s  %s\n", time.Now().Format("15:04:05.000"),
			fmt.Sprintf(format, args...))
	}
}

// Start boots the management core, the helpers of the active tunnel and the
// in-process data plane over the Android TUN fd. Returns "" on success or
// a JSON {"error": "..."} document.
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

	// Real-time activity file for diagnosing tunnel failures.
	tunnel.LogFunc = c.makeFileLogger(p.LogDir)

	cfgMgr, err := config.NewManager(p.ConfigPath)
	if err != nil {
		return errJSON(fmt.Errorf("config: %w", err))
	}

	vpn, err := core.NewVPNCoreWithOptions(cfgMgr, core.Options{EnableFeatures: false})
	if err != nil {
		cfgMgr.Close()
		return errJSON(fmt.Errorf("core: %w", err))
	}

	// RE-apply mobile binary layout AFTER constructing the core: the core
	// resets tunnel.BinDir from config.yaml, which may lack the mobile
	// filesDir/bin path. These params are authoritative on Android.
	tunnel.BinDir = p.BinDir
	tunnel.BinNames = p.BinNames
	tunnel.NativeSSH = p.NativeSSH

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

	// Helpers (ssh / dnstt / xray / zivpn processes exposing local SOCKS)
	// then the in-process data plane dialing the active SOCKS.
	if err := c.ensureHelpersLocked(c.activeID); err != nil {
		c.cleanupLocked()
		return errJSON(err)
	}
	if err := c.startDataplaneLocked(); err != nil {
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
	if c.stack != nil {
		c.stack.Close()
		c.stack.Wait()
		c.stack = nil
	}
	if c.dev != nil {
		c.dev.Close()
		c.dev = nil
	}
	c.tun = nil
	c.dialer = nil
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
	if c.logFile != nil {
		_ = c.logFile.Close()
		c.logFile = nil
	}
	tunnel.LogFunc = nil
	c.wg.Wait()
}

// ensureHelpersLocked starts the helper process of the active tunnel.
// Every tunnel type exposes a local SOCKS5 (native SSH, dnstt+SSH,
// Xray process, dnstt+Xray process, uz_core balancer) which the data
// plane dials.
func (c *Controller) ensureHelpersLocked(id string) error {
	t, ok := c.vpn.GetTunnelManager().Get(id)
	if !ok {
		return fmt.Errorf("tunnel not found: %s", id)
	}
	if t.Status() != tunnel.StatusRunning {
		if err := t.Start(c.ctx); err != nil {
			return fmt.Errorf("start tunnel %s: %w", t.Name(), err)
		}
	}
	return nil
}

// startDataplaneLocked builds the in-process gVisor stack over the Android
// TUN fd, upstreaming at the active tunnel's local SOCKS5 (caller holds
// c.mu).
func (c *Controller) startDataplaneLocked() error {
	t, ok := c.vpn.GetTunnelManager().Get(c.activeID)
	if !ok {
		return fmt.Errorf("active tunnel gone: %s", c.activeID)
	}
	socksAddr := tunnel.SocksAddr(t.Config())
	tunnel.Tracef("[dataplane] tunFd=%d mtu=%d upstream=%s", c.tunFd, c.mtu, socksAddr)

	dev, err := fdbased.Open(strconv.Itoa(c.tunFd), uint32(c.mtu), 0)
	if err != nil {
		return fmt.Errorf("open tun fd: %w", err)
	}

	upstream, err := t2proxy.NewSocks5(socksAddr, "", "")
	if err != nil {
		dev.Close()
		return fmt.Errorf("socks dialer: %w", err)
	}

	d := &swapDialer{}
	d.set(upstream)

	tun := t2tunnel.New(d, t2stat.DefaultManager)
	tun.ProcessAsync()

	st, err := t2core.CreateStack(&t2core.Config{
		LinkEndpoint:     dev,
		TransportHandler: tun,
	})
	if err != nil {
		dev.Close()
		return fmt.Errorf("netstack: %w", err)
	}

	c.dev = dev
	c.stack = st
	c.tun = tun
	c.dialer = d
	tunnel.Tracef("[dataplane] gVisor stack up")
	return nil
}

// switchUpstreamLocked re-points the data plane at the active tunnel.
func (c *Controller) switchUpstreamLocked() error {
	if c.dialer == nil {
		return fmt.Errorf("data plane not running")
	}
	t, ok := c.vpn.GetTunnelManager().Get(c.activeID)
	if !ok {
		return fmt.Errorf("active tunnel gone: %s", c.activeID)
	}
	socksAddr := tunnel.SocksAddr(t.Config())
	upstream, err := t2proxy.NewSocks5(socksAddr, "", "")
	if err != nil {
		return err
	}
	if err := waitTCP(socksAddr, 15*time.Second); err != nil {
		return fmt.Errorf("tunnel socks not ready (%s): %w", socksAddr, err)
	}
	c.dialer.set(upstream)
	tunnel.Tracef("[dataplane] upstream switched to %s", socksAddr)
	return nil
}

// followLoop migrates the data plane to any running tunnel when the active
// one dies (client asked with auto_follow).
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
			if !c.running || c.dialer == nil {
				c.mu.Unlock()
				continue
			}
			activeAlive := false
			if t, ok := c.vpn.GetTunnelManager().Get(c.activeID); ok {
				activeAlive = t.Status() == tunnel.StatusRunning
			}
			if !activeAlive {
				for _, cand := range c.vpn.GetTunnelManager().GetRunning() {
					c.activeID = cand.ID()
					if err := c.ensureHelpersLocked(c.activeID); err == nil {
						if err := c.switchUpstreamLocked(); err == nil {
							tunnel.Tracef("[dataplane] auto-follow migrated to %s", cand.Name())
						}
					}
					break
				}
			}
			c.mu.Unlock()
		}
	}
}

// SetActiveTunnel switches the data plane to the tunnel: helpers are
// ensured, then the upstream is switched.
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
	if err := c.switchUpstreamLocked(); err != nil {
		return errJSON(err)
	}
	return ""
}

// StartTunnel starts a tunnel helper process without touching the data plane.
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

// UpdateTunnel replaces a tunnel config (restarts helpers/upstream if active).
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
		if err := c.switchUpstreamLocked(); err != nil {
			return errJSON(err)
		}
	}
	return ""
}

// DeleteTunnel removes a tunnel (refused while it carries the data plane).
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
	snap := t2stat.DefaultManager.Snapshot()
	out["active_tunnel"] = c.activeID
	out["dataplane_running"] = c.dialer != nil
	out["uptime"] = int64(time.Since(c.startTime).Seconds())
	out["bytes_up"] = snap.UploadTotal
	out["bytes_down"] = snap.DownloadTotal
	out["tunnels"] = list

	b, _ := json.Marshal(out)
	return string(b)
}

// ---------------------------------------------------------------------------
// swapDialer: hot-swappable SOCKS5 upstream with DNS-over-TCP interception.
// ---------------------------------------------------------------------------

// swapDialer implements t2proxy.Dialer. UDP port 53 is relayed as
// DNS-over-TCP through the SOCKS proxy so DNS works with every tunnel type
// (SSH has no UDP support). All other traffic uses the upstream directly.
type swapDialer struct {
	v atomic.Value // stores t2proxy.Dialer
}

func (d *swapDialer) set(u t2proxy.Dialer) {
	d.v.Store(u)
}

func (d *swapDialer) get() t2proxy.Dialer {
	u := d.v.Load()
	if u == nil {
		return nil
	}
	return u.(t2proxy.Dialer)
}

func (d *swapDialer) DialContext(ctx context.Context, m *t2meta.Metadata) (net.Conn, error) {
	u := d.get()
	if u == nil {
		return nil, fmt.Errorf("no upstream proxy selected")
	}
	return u.DialContext(ctx, m)
}

func (d *swapDialer) DialUDP(m *t2meta.Metadata) (net.PacketConn, error) {
	u := d.get()
	if u == nil {
		return nil, fmt.Errorf("no upstream proxy selected")
	}
	if m.DstPort == 53 && m.DstIP.IsValid() {
		return newDNSOverTCPConn(u, m.DstIP), nil
	}
	return u.DialUDP(m)
}

// dnsOverTCPConn is a net.PacketConn relaying DNS datagrams over a
// DNS-over-TCP stream (RFC 7766 framing: uint16 length + message) opened
// through the SOCKS upstream to the original destination IP.
type dnsOverTCPConn struct {
	dial    t2proxy.Dialer
	dstIP   netip.Addr
	raddr   net.Addr
	respCh  chan []byte
	closeCh chan struct{}
	once    sync.Once
}

func newDNSOverTCPConn(u t2proxy.Dialer, dstIP netip.Addr) *dnsOverTCPConn {
	udpAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(dstIP, 53))
	return &dnsOverTCPConn{
		dial:    u,
		dstIP:   dstIP,
		raddr:   udpAddr,
		respCh:  make(chan []byte, 32),
		closeCh: make(chan struct{}),
	}
}

func (c *dnsOverTCPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closeCh:
		return 0, fmt.Errorf("dns relay closed")
	default:
	}
	payload := append([]byte(nil), b...)
	go c.relay(payload)
	return len(b), nil
}

func (c *dnsOverTCPConn) relay(query []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := c.dial.DialContext(ctx, &t2meta.Metadata{
		Network: t2meta.TCP,
		DstIP:   c.dstIP,
		DstPort: 53,
	})
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	if _, err := conn.Write(append(hdr[:], query...)); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(hdr[:])))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return
	}
	select {
	case c.respCh <- resp:
	case <-c.closeCh:
	}
}

func (c *dnsOverTCPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case resp := <-c.respCh:
		n := copy(b, resp)
		return n, c.raddr, nil
	case <-c.closeCh:
		return 0, nil, fmt.Errorf("dns relay closed")
	}
}

func (c *dnsOverTCPConn) Close() error {
	c.once.Do(func() { close(c.closeCh) })
	return nil
}

func (c *dnsOverTCPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *dnsOverTCPConn) RemoteAddr() net.Addr { return c.raddr }

func (c *dnsOverTCPConn) SetDeadline(t time.Time) error      { return nil }
func (c *dnsOverTCPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dnsOverTCPConn) SetWriteDeadline(t time.Time) error { return nil }

// ---------------------------------------------------------------------------
// Offline helpers (no running Controller needed). Used by the native UI to
// manage tunnels and parse links while disconnected.
// ---------------------------------------------------------------------------

// ParseLink parses a subscription link into a TunnelConfig JSON document.
func ParseLink(link string) string {
	tc, err := tunnel.ParseXrayLink(link)
	if err != nil {
		return errJSON(err)
	}
	b, err := json.Marshal(tc)
	if err != nil {
		return errJSON(err)
	}
	return string(b)
}

// openConfigManager opens the config file (creating defaults if missing).
func openConfigManager(configPath string) (*config.Manager, error) {
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return nil, err
	}
	return config.NewManager(configPath)
}

// ConfigAdd appends a tunnel (TunnelConfig JSON) to the config file.
func ConfigAdd(configPath, tunnelJSON string) string {
	var tc config.TunnelConfig
	if err := json.Unmarshal([]byte(tunnelJSON), &tc); err != nil {
		return errJSON(fmt.Errorf("invalid tunnel: %w", err))
	}
	mgr, err := openConfigManager(configPath)
	if err != nil {
		return errJSON(err)
	}
	defer mgr.Close()
	if err := mgr.AddTunnel(&tc); err != nil {
		return errJSON(err)
	}
	b, _ := json.Marshal(map[string]string{"id": tc.ID})
	return string(b)
}

// ConfigUpdate replaces a tunnel in the config file.
func ConfigUpdate(configPath, id, tunnelJSON string) string {
	var tc config.TunnelConfig
	if err := json.Unmarshal([]byte(tunnelJSON), &tc); err != nil {
		return errJSON(fmt.Errorf("invalid tunnel: %w", err))
	}
	tc.ID = id
	mgr, err := openConfigManager(configPath)
	if err != nil {
		return errJSON(err)
	}
	defer mgr.Close()
	if err := mgr.UpdateTunnel(id, tc); err != nil {
		return errJSON(err)
	}
	return ""
}

// ConfigDelete removes a tunnel from the config file.
func ConfigDelete(configPath, id string) string {
	mgr, err := openConfigManager(configPath)
	if err != nil {
		return errJSON(err)
	}
	defer mgr.Close()
	if err := mgr.DeleteTunnel(id); err != nil {
		return errJSON(err)
	}
	return ""
}

// ListTunnels returns the full TunnelConfig array from the config file
// (used by the native UI, online or offline).
func ListTunnels(configPath string) string {
	mgr, err := openConfigManager(configPath)
	if err != nil {
		return errJSON(err)
	}
	defer mgr.Close()
	out := mgr.Get().Tunnels
	if out == nil {
		out = []config.TunnelConfig{}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// SocksAddrFor returns the local SOCKS endpoint of a tunnel
// ({"socks":"127.0.0.1:port","type":"..."}) without starting anything.
// Used by the native UDP-DNS ping while connected.
func SocksAddrFor(configPath, id string) string {
	mgr, err := openConfigManager(configPath)
	if err != nil {
		return errJSON(err)
	}
	defer mgr.Close()
	for i := range mgr.Get().Tunnels {
		tc := &mgr.Get().Tunnels[i]
		if tc.ID == id {
			b, _ := json.Marshal(map[string]string{
				"socks": tunnel.SocksAddr(tc),
				"type":  string(tc.Type),
			})
			return string(b)
		}
	}
	return errJSON(fmt.Errorf("tunnel not found: %s", id))
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
