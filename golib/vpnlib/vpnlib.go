package vpnlib

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
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

	DNSIP string `json:"dns_ip"`

	DNSProtect *bool `json:"dns_protect"`

	DNSSecondary string `json:"dns_secondary"`

	TCPNoDelay *bool `json:"tcp_nodelay"`

	DnsttTCP *bool `json:"dnstt_tcp"`

	UDPGWListen string `json:"udpgw_listen"`

	UDPGWEnabled *bool `json:"udpgw_enabled"`

	RoundRobin string `json:"round_robin"`

	LogDir string `json:"log_dir"`

	LogQuiet *bool `json:"log_quiet"`

	TmpDir string `json:"tmp_dir"`
}

type Controller struct {
	mu      sync.Mutex
	running bool

	abort        atomic.Bool
	cancelHolder atomic.Value

	hardKilled atomic.Bool

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

	front      *exec.Cmd
	frontCfg   string
	frontAlive bool
	frontPort  int
	rrIDs      []string

	tunFd      int
	mtu        int
	configPath string
	activeID   string
	autoFollow bool
	dnsIP      string
	dnsProtect bool
	startTime  time.Time
	logFile    *os.File
	logPath    string
	rrLastTry  map[string]time.Time

	// stopRequested est mis à true par Stop() quand le mutex du contrôleur
	// est retenu par un Start() en vol : Stop() ferme alors immédiatement le
	// fd TUN et retourne sans attendre, afin de ne jamais bloquer le caller
	// Java ni déclencher le watchdog kill du processus. Le Start() en vol,
	// dont le contexte est annulé, échoue et effectue son propre cleanupLocked
	// idempotent quand il relâche le mutex.
	stopRequested atomic.Bool
}

func NewController() *Controller {
	return &Controller{}
}

func MobileVersion() string {
	return "2.1.0-tun2socks"
}

func errJSON(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}

func (c *Controller) makeFileLogger(logDir string) func(string, ...interface{}) {

	path, f, ok := c.openLog(logDir)
	if !ok {

		home, herr := os.UserHomeDir()
		if herr != nil || home == "" {
			home = "."
		}
		fallback := filepath.Join(home, ".tasmol", "logs")
		if ferr := os.MkdirAll(fallback, 0755); ferr == nil {
			path, f, ok = c.openLog(fallback)
		}
	}
	if !ok {

		c.logFile = nil
		return func(format string, args ...interface{}) {}
	}
	c.logFile = f
	c.logPath = path

	var mu sync.Mutex

	tunnel.DirectLog = func(line string) {
		mu.Lock()
		defer mu.Unlock()
		if c.logFile == nil {
			return
		}
		fmt.Fprintf(c.logFile, "%s  %s\n", time.Now().Format("15:04:05.000"), line)
	}

	return func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		if c.logFile == nil {
			return
		}
		fmt.Fprintf(c.logFile, "%s  %s\n", time.Now().Format("15:04:05.000"),
			sanitizeLogLine(fmt.Sprintf(format, args...)))
	}
}

func (c *Controller) openLog(logDir string) (string, *os.File, bool) {
	if logDir == "" {
		return "", nil, false
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", nil, false
	}
	path := filepath.Join(logDir, tunnel.LogFileName())
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return "", nil, false
	}
	return path, f, true
}

func sanitizeLogLine(line string) string {
	line = logSecretRe.ReplaceAllString(line, `$1"••••••"`)
	line = logUUIDRe.ReplaceAllString(line, "[UUID]")
	line = logLinkRe.ReplaceAllString(line, "[tunnel link]")
	line = logPassEqRe.ReplaceAllString(line, `$1"••••••"`)
	line = logPubkeyRe.ReplaceAllString(line, `$1••••••`)
	return line
}

var (
	logSecretRe = regexp.MustCompile(`(?i)("(?:password|pass|auth|obfs|token|secret|private[_-]?key|uuid|publicKey|pkey|sshPassword)"\s*:\s*)"[^"]*"`)
	logUUIDRe   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	logLinkRe   = regexp.MustCompile(`(?i)\b(?:vmess|vless|trojan|ss)://[^\s"'<>]+`)
	logPassEqRe = regexp.MustCompile(`(?i)\b(password|passwd)\s*=\s*"[^"]*"`)
	logPubkeyRe = regexp.MustCompile(`(-pubkey\s+)[0-9a-fA-F]{8,}`)
)

func (c *Controller) Start(paramsJSON string) string {

	if c.abort.Load() {
		return errJSON(errors.New("aborted"))
	}
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

	tunnel.BinDir = p.BinDir
	tunnel.BinNames = p.BinNames
	tunnel.NativeSSH = p.NativeSSH
	tunnel.TmpDir = p.TmpDir
	tunnel.DNSPrimary = strings.TrimSpace(p.DNSIP)
	tunnel.DNSSecondary = strings.TrimSpace(p.DNSSecondary)
	tunnel.TCPNoDelay = p.TCPNoDelay == nil || *p.TCPNoDelay
	tunnel.DnsttUseTCP = p.DnsttTCP != nil && *p.DnsttTCP

	tunnel.LogFunc = c.makeFileLogger(p.LogDir)

	tunnel.QuietLog = p.LogQuiet == nil || *p.LogQuiet
	tunnel.Connf("session", "starting session")

	cfgMgr, err := config.NewManager(p.ConfigPath)
	if err != nil {
		return errJSON(fmt.Errorf("config: %w", err))
	}

	if cfg := cfgMgr.Get(); cfg != nil {
		if listen := strings.TrimSpace(p.UDPGWListen); listen != "" {
			if !strings.Contains(listen, ":") {
				listen = "127.0.0.1:" + listen
			}
			cfg.UDPGW.ListenAddr = listen
			tunnel.Connf("session", "UDPGW listen %s (profile)", cfg.UDPGW.ListenAddr)
		}
		if p.UDPGWEnabled != nil {
			cfg.UDPGW.Enabled = *p.UDPGWEnabled
		}
	}

	vpn, err := core.NewVPNCoreWithOptions(cfgMgr, core.Options{EnableFeatures: false})
	if err != nil {
		cfgMgr.Close()
		return errJSON(fmt.Errorf("core: %w", err))
	}

	tunnel.BinDir = p.BinDir
	tunnel.BinNames = p.BinNames
	tunnel.NativeSSH = p.NativeSSH
	tunnel.TmpDir = p.TmpDir
	tunnel.DNSPrimary = strings.TrimSpace(p.DNSIP)
	tunnel.DNSSecondary = strings.TrimSpace(p.DNSSecondary)
	tunnel.TCPNoDelay = p.TCPNoDelay == nil || *p.TCPNoDelay
	tunnel.DnsttUseTCP = p.DnsttTCP != nil && *p.DnsttTCP

	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.cancelHolder.Store(context.CancelFunc(c.cancel))
	c.cfgMgr = cfgMgr
	c.vpn = vpn
	c.tunFd = p.TunFd
	c.mtu = p.MTU
	c.configPath = p.ConfigPath
	c.autoFollow = p.AutoFollow
	c.dnsIP = p.DNSIP
	if strings.TrimSpace(c.dnsIP) == "" {
		c.dnsIP = "8.8.8.8"
	}
	c.dnsProtect = p.DNSProtect == nil || *p.DNSProtect
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

	c.rrIDs = parseRoundRobin(p.RoundRobin, cfgMgr)
	if c.abort.Load() || c.stopRequested.Load() {
		c.cleanupLocked()
		return errJSON(errors.New("aborted"))
	}
	if len(c.rrIDs) >= 2 {
		tunnel.Tracef("[rr] mode=round-robin with %d profiles", len(c.rrIDs))
	} else {
		tunnel.Connf("session", "mode=single active=%q", c.activeID)
	}
	if len(c.rrIDs) >= 2 {
		tunnel.Tracef("[rr] members confirmed: %d profiles", len(c.rrIDs))
		if err := c.ensureHelpersNLocked(c.rrIDs); err != nil {
			c.cleanupLocked()
			return errJSON(err)
		}
		if err := c.startBalancerFrontLocked(); err != nil {
			c.cleanupLocked()
			return errJSON(err)
		}
	} else {
		c.rrIDs = nil
		if err := c.ensureHelpersLocked(c.activeID); err != nil {
			c.cleanupLocked()
			return errJSON(err)
		}
	}
	if c.abort.Load() {
		c.cleanupLocked()
		return errJSON(errors.New("aborted"))
	}
	if err := c.startDataplaneLocked(); err != nil {
		c.cleanupLocked()
		return errJSON(err)
	}
	if c.abort.Load() || c.stopRequested.Load() {
		c.cleanupLocked()
		return errJSON(errors.New("aborted"))
	}

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

func (c *Controller) ApiSocksAddr(activeTunnelID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running && c.frontPort != 0 && len(c.rrIDs) >= 2 {
		return fmt.Sprintf("127.0.0.1:%d", c.frontPort)
	}
	if activeTunnelID != "" {
		if a := tunnel.LiveSocksAddr(activeTunnelID); a != "" {
			return a
		}
	}
	return ""
}

func (c *Controller) Stop() (out string) {

	defer func() {
		if r := recover(); r != nil {
			tunnel.Errorf("session", "stop panic (swallowed): %v", r)
			c.running = false
			out = ""
		}
	}()

	c.abort.Store(true)
	// NOTE: ne PAS appeler c.cancel() ici. En path contended (Start() tient
	// le mutex), annuler le contexte maintenant ferait échouer t.Start(c.ctx)
	// avec "context canceled" alors qu'une nouvelle connexion essaie de
	// démarrer. L'annulation a lieu après acquisition du mutex (fast path
	// ligne 411, ou goroutine différée ligne 431) quand Start() a relâché
	// le mutex.

	if c.mu.TryLock() {
		c.running = false
		if c.cancel != nil {
			c.cancel()
		}
		c.mu.Unlock()

		waitBounded(c.wg.Wait, 1*time.Second, "followLoop exit")
		c.mu.Lock()
		defer c.mu.Unlock()
		c.cleanupLocked()
		return ""
	}

	c.stopRequested.Store(true)
	c.hardKillTunFd()
	go func() {
		defer func() {

			_ = recover()
		}()
		c.mu.Lock()
		c.running = false
		if c.cancel != nil {
			c.cancel()
		}
		c.mu.Unlock()
		waitBounded(c.wg.Wait, 1*time.Second, "followLoop exit (deferred)")
		c.mu.Lock()
		c.cleanupLocked()
		c.mu.Unlock()
	}()
	return ""
}

func (c *Controller) hardKillTunFd() {
	if c.hardKilled.Swap(true) {
		return
	}
	if fd := c.tunFd; fd > 0 {
		_ = unix.Close(fd)
	}
}

func waitBounded(wait func(), d time.Duration, what string) {
	done := make(chan struct{})
	go func() {

		defer func() {
			if r := recover(); r != nil {
				tunnel.Warnf("session", "teardown panic in %s: %v", what, r)
			}
		}()
		wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		tunnel.Warnf("session", "teardown: %s did not finish in %v, continuing anyway", what, d)
	}
}

func safeCall(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			tunnel.Warnf("session", "teardown panic in %s: %v", what, r)
		}
	}()
	fn()
}

func (c *Controller) cleanupLocked() {
	if c.cancel != nil {
		c.cancel()
	}
	safeCall("killFront", func() { c.killFrontLocked() })
	if c.stack != nil {
		st := c.stack
		c.stack = nil
		safeCall("stack.Close", func() { st.Close() })
		waitBounded(st.Wait, 1*time.Second, "tun2socks drain")
	}
	if c.dev != nil {
		d := c.dev
		c.dev = nil
		safeCall("dev.Close", func() { d.Close() })
	}
	c.tun = nil
	c.dialer = nil
	c.rrIDs = nil
	if c.vpn != nil {
		v := c.vpn
		c.vpn = nil

		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		waitBounded(func() { _ = v.Stop(stopCtx) }, 3*time.Second, "tunnels stop")
		cancel()
	}
	if c.cfgMgr != nil {
		m := c.cfgMgr
		c.cfgMgr = nil
		safeCall("cfgMgr.Close", func() { _ = m.Close() })
	}
	c.apiSrv = nil
	c.running = false
	c.activeID = ""
	if c.logFile != nil {
		f := c.logFile
		c.logFile = nil
		safeCall("logFile.Close", func() { _ = f.Close() })
	}
	tunnel.LogFunc = nil
}

func (c *Controller) ensureHelpersLocked(id string) error {
	t, ok := c.vpn.GetTunnelManager().Get(id)
	if !ok {
		tunnel.Errorf("session", "helper id=%s not found in config", id)
		return fmt.Errorf("tunnel not found: %s", id)
	}
	if t.Status() != tunnel.StatusRunning {
		tunnel.Journalf("session", "starting helper %q", t.Name())
		if err := t.Start(c.ctx); err != nil {
			tunnel.Errorf("session", "helper %q failed: %v", t.Name(), err)
			return fmt.Errorf("start tunnel %s: %w", t.Name(), err)
		}
		tunnel.Tracef("[session] helper %q running, socks=%s", t.Name(), tunnel.SocksAddr(t.Config()))
	} else {
		tunnel.Tracef("[session] helper %q already running, socks=%s", t.Name(), tunnel.SocksAddr(t.Config()))
	}
	return nil
}

func parseRoundRobin(csv string, cfgMgr *config.Manager) []string {
	var out []string
	seen := map[string]bool{}
	known := map[string]bool{}
	for _, tc := range cfgMgr.Get().Tunnels {
		known[tc.ID] = true
	}
	for _, part := range strings.Split(csv, ",") {
		id := strings.TrimSpace(part)
		if id == "" || seen[id] || !known[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func (c *Controller) ensureHelperRetryLocked(id string) error {
	t, ok := c.vpn.GetTunnelManager().Get(id)
	if !ok {
		return fmt.Errorf("tunnel not found: %s", id)
	}
	if t.Status() == tunnel.StatusRunning {
		return nil
	}
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		tunnel.Tracef("[rr] starting %s (attempt %d/3)", t.Name(), attempt)
		if err = t.Start(c.ctx); err == nil {
			tunnel.Tracef("[rr] %s up, socks=%s", t.Name(), tunnel.SocksAddr(t.Config()))
			return nil
		}
		_ = t.Stop(context.Background())
		tunnel.Warnf("rr", "%s attempt %d failed: %v", t.Name(), attempt, err)
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("tunnel %s failed after 3 attempts: %w", t.Name(), err)
}

func (c *Controller) ensureHelpersNLocked(ids []string) error {
	type result struct {
		id  string
		err error
	}
	resCh := make(chan result, len(ids))
	for _, id := range ids {
		go func(id string) {
			resCh <- result{id, c.ensureHelperRetryLocked(id)}
		}(id)
	}
	var okIDs []string
	var lastErr error

	byID := map[string]error{}
	for range ids {
		r := <-resCh
		byID[r.id] = r.err
	}
	for _, id := range ids {
		if err := byID[id]; err != nil {
			tunnel.Tracef("[rr] dropping profile %s: %v", id, err)
			lastErr = err
			continue
		}
		okIDs = append(okIDs, id)
	}
	if len(okIDs) < 2 {
		if lastErr == nil {
			lastErr = fmt.Errorf("fewer than 2 profiles usable")
		}
		return lastErr
	}
	c.rrIDs = okIDs
	return nil
}

func (c *Controller) startBalancerFrontLocked() error {
	var profiles []*config.TunnelConfig
	for _, id := range c.rrIDs {
		t, ok := c.vpn.GetTunnelManager().Get(id)
		if !ok {
			return fmt.Errorf("round-robin tunnel gone: %s", id)
		}
		profiles = append(profiles, t.Config())
		tunnel.Tracef("[rr-front] member %q type=%s live=%s",
			t.Name(), t.Type(), tunnel.SocksAddr(t.Config()))
	}

	frontPort, err := tunnel.PickFreePort()
	if err != nil {
		return fmt.Errorf("round-robin front port: %w", err)
	}
	raw, err := tunnel.BuildBalancerFront(profiles, frontPort)
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(filepath.Dir(c.configPath), "front-rr.json")
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		return fmt.Errorf("write front config: %w", err)
	}

	bin := tunnel.LookupBin(tunnel.BinDir, tunnel.BinXray)
	tunnel.Tracef("[rr-front] binary=%q profiles=%d", bin, len(profiles))
	cmd := exec.Command(bin, "run", "-c", cfgPath)
	if tunnel.BinDir != "" {
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+tunnel.BinDir)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.Remove(cfgPath)
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.Remove(cfgPath)
		return err
	}
	if err := cmd.Start(); err != nil {
		os.Remove(cfgPath)
		return fmt.Errorf("round-robin front start: %w", err)
	}
	tunnel.Tracef("[rr-front] process started pid=%d", cmd.Process.Pid)

	c.front = cmd
	c.frontCfg = cfgPath
	c.frontAlive = true
	c.frontPort = frontPort
	go tunnel.PipeLinesToLog(stdout, "[rr-front][out]")
	go tunnel.PipeLinesToLog(stderr, "[rr-front][err]")
	go c.watchFront(cmd)

	frontAddr := fmt.Sprintf("127.0.0.1:%d", frontPort)
	if err := waitTCP(frontAddr, 15*time.Second); err != nil {
		c.killFrontLocked()
		return fmt.Errorf("round-robin front not ready: %w", err)
	}
	tunnel.Tracef("[rr-front] SOCKS %s ready", frontAddr)
	return nil
}

func (c *Controller) killFrontLocked() {
	if c.front != nil && c.front.Process != nil {
		_ = c.front.Process.Kill()
		_, _ = c.front.Process.Wait()
	}
	c.front = nil
	c.frontAlive = false
	c.frontPort = 0
	if c.frontCfg != "" {
		os.Remove(c.frontCfg)
		c.frontCfg = ""
	}
}

func (c *Controller) watchFront(cmd *exec.Cmd) {
	err := cmd.Wait()
	tunnel.Tracef("[rr-front] process exited: %v", err)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.front == cmd {
		c.frontAlive = false
	}
}

func (c *Controller) rebuildBalancerFrontLocked(ids []string) error {
	c.killFrontLocked()
	c.rrIDs = ids
	return c.startBalancerFrontLocked()
}

func (c *Controller) startDataplaneLocked() error {
	socksAddr := fmt.Sprintf("127.0.0.1:%d", c.frontPort)
	if len(c.rrIDs) < 2 {
		t, ok := c.vpn.GetTunnelManager().Get(c.activeID)
		if !ok {
			return fmt.Errorf("active tunnel gone: %s", c.activeID)
		}
		socksAddr = tunnel.SocksAddr(t.Config())
	}
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

	d := newSwapDialer(c.dnsIP, c.dnsProtect)
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
	tunnel.Tracef("[dataplane] gVisor stack up, session RUNNING")
	return nil
}

func (c *Controller) switchUpstreamLocked() error {
	if c.dialer == nil {
		return fmt.Errorf("data plane not running")
	}
	var socksAddr string
	if len(c.rrIDs) >= 2 {
		if c.frontPort <= 0 {
			return fmt.Errorf("round-robin front has no port")
		}
		socksAddr = fmt.Sprintf("127.0.0.1:%d", c.frontPort)
	} else {
		t, ok := c.vpn.GetTunnelManager().Get(c.activeID)
		if !ok {
			return fmt.Errorf("active tunnel gone: %s", c.activeID)
		}
		socksAddr = tunnel.SocksAddr(t.Config())
	}
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

func (c *Controller) followRoundRobinLocked() {
	if c.rrLastTry == nil {
		c.rrLastTry = make(map[string]time.Time)
	}
	var alive []string
	now := time.Now()
	revived := false
	for _, id := range c.rrIDs {
		t, ok := c.vpn.GetTunnelManager().Get(id)
		if !ok {
			continue
		}
		if t.Status() != tunnel.StatusRunning {
			if last, tried := c.rrLastTry[id]; !tried || now.Sub(last) > time.Minute {
				c.rrLastTry[id] = now
				tunnel.Tracef("[rr] revive attempt for %s", t.Name())
				if err := t.Start(c.ctx); err != nil {
					tunnel.Warnf("rr", "revive %s failed: %v", t.Name(), err)
					continue
				}

				revived = true
			} else {
				continue
			}
		}
		if t.Status() == tunnel.StatusRunning {
			alive = append(alive, id)
		}
	}
	if len(alive) >= 2 && (!c.frontAlive || !sameIDSet(alive, c.rrIDs) || revived) {
		tunnel.Tracef("[rr] rebuilding front with %d profiles", len(alive))
		if err := c.rebuildBalancerFrontLocked(alive); err != nil {
			tunnel.Errorf("rr", "rebuild failed: %v", err)
			return
		}

		if err := c.switchUpstreamLocked(); err != nil {
			tunnel.Tracef("[rr] re-point after rebuild failed: %v", err)
		}
		return
	}
	if len(alive) < 2 && c.frontAlive {
		tunnel.Tracef("[rr] degraded: %d/2+ profiles alive", len(alive))
	}
}

func sameIDSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool, len(a))
	for _, id := range a {
		m[id] = true
	}
	for _, id := range b {
		if !m[id] {
			return false
		}
	}
	return true
}

func (c *Controller) throttledRestartLocked(t tunnel.Tunnel) bool {
	if c.rrLastTry == nil {
		c.rrLastTry = make(map[string]time.Time)
	}
	if last, tried := c.rrLastTry[t.ID()]; tried && time.Since(last) < time.Minute {
		return false
	}
	c.rrLastTry[t.ID()] = time.Now()
	tunnel.Tracef("[dataplane] restarting dead tunnel %s", t.Name())
	_ = t.Stop(context.Background())
	if err := t.Start(c.ctx); err != nil {
		tunnel.Warnf("dataplane", "restart %s failed: %v", t.Name(), err)
		return false
	}
	if err := c.switchUpstreamLocked(); err != nil {
		tunnel.Warnf("dataplane", "re-point upstream failed: %v", err)
		return false
	}
	tunnel.Tracef("[dataplane] restarted %s", t.Name())
	return true
}

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
			if len(c.rrIDs) >= 2 {
				c.followRoundRobinLocked()
				c.mu.Unlock()
				continue
			}
			activeAlive := false
			if t, ok := c.vpn.GetTunnelManager().Get(c.activeID); ok {
				activeAlive = t.Status() == tunnel.StatusRunning
			}
			if !activeAlive {

				if t, ok := c.vpn.GetTunnelManager().Get(c.activeID); ok {
					if c.throttledRestartLocked(t) {
						c.mu.Unlock()
						continue
					}
				}
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

func (c *Controller) SetActiveTunnel(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return errJSON(fmt.Errorf("controller not running"))
	}
	if _, ok := c.vpn.GetTunnelManager().Get(id); !ok {
		return errJSON(fmt.Errorf("tunnel not found: %s", id))
	}
	if len(c.rrIDs) >= 2 {
		tunnel.Tracef("[rr] leaving round-robin mode for single tunnel %s", id)
		c.killFrontLocked()
		c.rrIDs = nil
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
	out["round_robin"] = c.rrIDs
	out["front_running"] = c.frontAlive
	out["uptime"] = int64(time.Since(c.startTime).Seconds())
	out["bytes_up"] = snap.UploadTotal
	out["bytes_down"] = snap.DownloadTotal
	out["tunnels"] = list

	b, _ := json.Marshal(out)
	return string(b)
}

type swapDialer struct {
	v          atomic.Value
	dnsIP      netip.Addr
	protectDNS bool
}

func newSwapDialer(dnsIP string, protectDNS bool) *swapDialer {
	d := &swapDialer{protectDNS: protectDNS}
	if ip, err := netip.ParseAddr(strings.TrimSpace(dnsIP)); err == nil {
		d.dnsIP = ip
	} else {
		d.dnsIP = netip.MustParseAddr("8.8.8.8")
	}
	return d
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
	if m.DstPort == 53 && m.DstIP.IsValid() && d.protectDNS {
		tunnel.Tracef("[dns] hijack %s -> %s (forced resolver)", m.DstIP, d.dnsIP)
		return newDNSOverTCPConn(u, m.DstIP, d.dnsIP), nil
	}
	return u.DialUDP(m)
}

type dnsOverTCPConn struct {
	dial    t2proxy.Dialer
	dialIP  netip.Addr
	raddr   net.Addr
	respCh  chan []byte
	closeCh chan struct{}
	once    sync.Once
}

func newDNSOverTCPConn(u t2proxy.Dialer, origDst, dialIP netip.Addr) *dnsOverTCPConn {
	udpAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(origDst, 53))
	return &dnsOverTCPConn{
		dial:    u,
		dialIP:  dialIP,
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := c.dial.DialContext(ctx, &t2meta.Metadata{
		Network: t2meta.TCP,
		DstIP:   c.dialIP,
		DstPort: 53,
	})
	if err != nil {
		tunnel.Tracef("[dns] dial %s:53 failed: %v", c.dialIP, err)
		return
	}
	defer conn.Close()
	t0 := time.Now()
	_ = conn.SetDeadline(t0.Add(30 * time.Second))

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	if _, err := conn.Write(append(hdr[:], query...)); err != nil {
		tunnel.Tracef("[dns] query write failed after %v: %v", time.Since(t0), err)
		return
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {

		tunnel.Tracef("[dns] query timeout after %v (réponse jamais reçue): %v", time.Since(t0), err)
		return
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(hdr[:])))
	if _, err := io.ReadFull(conn, resp); err != nil {
		tunnel.Tracef("[dns] read from %s:53 failed after %v: %v", c.dialIP, time.Since(t0), err)
		return
	}
	tunnel.Tracef("[dns] query ok in %v (%d B)", time.Since(t0), len(resp))
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

func openConfigManager(configPath string) (*config.Manager, error) {
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return nil, err
	}
	return config.NewManager(configPath)
}

func ConfigAdd(configPath, tunnelJSON string) string {
	var tc config.TunnelConfig
	if err := json.Unmarshal([]byte(tunnelJSON), &tc); err != nil {
		return errJSON(fmt.Errorf("invalid tunnel: %w", err))
	}
	tunnel.Tracef("[config] add type=%s name=%q pubkeyLen=%d",
		tc.Type, tc.Name, len(tc.Server.PublicKey))
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

func ConfigUpdate(configPath, id, tunnelJSON string) string {
	var tc config.TunnelConfig
	if err := json.Unmarshal([]byte(tunnelJSON), &tc); err != nil {
		return errJSON(fmt.Errorf("invalid tunnel: %w", err))
	}
	tc.ID = id
	tunnel.Tracef("[config] update id=%s type=%s name=%q pubkeyLen=%d",
		id, tc.Type, tc.Name, len(tc.Server.PublicKey))
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

func ListTunnels(configPath string) string {
	mgr, err := openConfigManager(configPath)
	if err != nil {
		return errJSON(err)
	}
	defer mgr.Close()
	out := mgr.Get().Tunnels

	for _, tc := range out {
		if tc.Type == config.TunnelSSHSlowDNS || tc.Type == config.TunnelXraySlowDNS || tc.Type == config.TunnelZivpn {
			tunnel.Tracef("[config] list id=%s type=%s name=%q pubkeyLen=%d",
				tc.ID, tc.Type, tc.Name, len(tc.Server.PublicKey))
		}
	}
	if out == nil {
		out = []config.TunnelConfig{}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

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
