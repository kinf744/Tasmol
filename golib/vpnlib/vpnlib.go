// Package vpnlib is the gomobile entry point for the Android application
// (Voie B, no-root operation).
//
// Architecture: the Android VpnService captures device packets into a TUN
// file descriptor and hands it to Controller.Start. The data plane
// (gVisor netstack via xjasonlyu/tun2socks) forwards TCP through the local
// SOCKS5 proxy exposed by the active tunnel (SSH / dnstt+SSH / Xray /
// dnstt+Xray / Zivpn). UDP DNS (port 53) is relayed over DNS-over-TCP
// through the same SOCKS proxy so it works with every tunnel type,
// including SSH which has no UDP support. Other UDP goes through SOCKS5
// UDP ASSOCIATE (supported by Xray/Zivpn outbounds).
//
// The app's own UID is excluded from the VPN via
// VpnService.Builder.addDisallowedApplication, so upstream sockets
// (tunnel processes, SOCKS dials) never loop back into the TUN.
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

	activeID   string
	autoFollow bool
}

// NewController creates a Controller. It must be called once.
func NewController() *Controller {
	return &Controller{}
}

// MobileVersion returns the data-plane version.
func MobileVersion() string {
	return Version
}

func errJSON(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}

// Start boots the management core, the active tunnel and the TUN data
// plane. paramsJSON follows startParams. Returns "" on success or a JSON
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

	// Wire tunnel engines: bundled official binaries + native SSH, exactly
	// like the server build but without external openssh.
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
	c.activeID = p.ActiveTunnel
	c.autoFollow = p.AutoFollow

	// Start the requested tunnel (or the first enabled one).
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
	if err := c.startTunnelLocked(c.activeID); err != nil {
		c.cleanupLocked()
		return errJSON(err)
	}

	// Data plane: gVisor stack on the Android TUN fd, upstream = the
	// active tunnel's local SOCKS5.
	if err := c.startDataplaneLocked(p.TunFd, p.MTU); err != nil {
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
	c.wg.Wait()
}

// startTunnelLocked starts a tunnel process by id (caller holds c.mu).
func (c *Controller) startTunnelLocked(id string) error {
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

// startDataplaneLocked builds the gVisor stack over tunFd (caller holds c.mu).
func (c *Controller) startDataplaneLocked(tunFd, mtu int) error {
	socksAddr, err := c.activeSocksLocked()
	if err != nil {
		return err
	}

	dev, err := fdbased.Open(strconv.Itoa(tunFd), uint32(mtu), 0)
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

	t := t2tunnel.New(d, t2stat.DefaultManager)
	t.ProcessAsync()

	st, err := t2core.CreateStack(&t2core.Config{
		LinkEndpoint:     dev,
		TransportHandler: t,
	})
	if err != nil {
		dev.Close()
		return fmt.Errorf("netstack: %w", err)
	}

	c.dev = dev
	c.stack = st
	c.tun = t
	c.dialer = d
	return nil
}

// activeSocksLocked resolves the SOCKS endpoint of the active tunnel.
func (c *Controller) activeSocksLocked() (string, error) {
	t, ok := c.vpn.GetTunnelManager().Get(c.activeID)
	if !ok {
		return "", fmt.Errorf("active tunnel gone: %s", c.activeID)
	}
	return tunnel.SocksAddr(t.Config()), nil
}

// switchUpstreamLocked re-points the data plane at the active tunnel.
func (c *Controller) switchUpstreamLocked() error {
	if c.dialer == nil {
		return fmt.Errorf("data plane not running")
	}
	socksAddr, err := c.activeSocksLocked()
	if err != nil {
		return err
	}
	upstream, err := t2proxy.NewSocks5(socksAddr, "", "")
	if err != nil {
		return err
	}
	// Make sure the SOCKS endpoint answers before switching.
	if err := waitTCP(socksAddr, 15*time.Second); err != nil {
		return fmt.Errorf("tunnel socks not ready (%s): %w", socksAddr, err)
	}
	c.dialer.set(upstream)
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
			need := false
			if t, ok := c.vpn.GetTunnelManager().Get(c.activeID); !ok || t.Status() != tunnel.StatusRunning {
				need = true
				for _, cand := range c.vpn.GetTunnelManager().GetRunning() {
					c.activeID = cand.ID()
					need = false
					break
				}
			}
			if need {
				c.mu.Unlock()
				continue
			}
			_ = c.switchUpstreamLocked()
			c.mu.Unlock()
		}
	}
}

// SetActiveTunnel starts the tunnel and switches the data plane to it.
// Returns "" on success or a JSON error.
func (c *Controller) SetActiveTunnel(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	if err := c.startTunnelLocked(id); err != nil {
		return errJSON(err)
	}
	c.activeID = id
	if err := c.switchUpstreamLocked(); err != nil {
		return errJSON(err)
	}
	return ""
}

// StartTunnel starts a tunnel process without touching the data plane.
func (c *Controller) StartTunnel(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	if err := c.startTunnelLocked(id); err != nil {
		return errJSON(err)
	}
	return ""
}

// StopTunnel stops a tunnel process.
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
// Returns {"id": "..."} or a JSON error.
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

// UpdateTunnel replaces a tunnel config (restarts it if running).
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
	wasRunning := false
	if old, ok := c.vpn.GetTunnelManager().Get(id); ok {
		wasRunning = old.Status() == tunnel.StatusRunning
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
	if wasRunning || wasActive {
		if err := c.startTunnelLocked(id); err != nil {
			return errJSON(err)
		}
		if wasActive {
			if err := c.switchUpstreamLocked(); err != nil {
				return errJSON(err)
			}
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
	var err error
	trimmed := content
	for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\n' || trimmed[0] == '\t' || trimmed[0] == '\r') {
		trimmed = trimmed[1:]
	}
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
	out["tunnels"] = list
	out["bytes_up"] = snap.UploadTotal
	out["bytes_down"] = snap.DownloadTotal

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
