package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpn-app/internal/config"
)

// ZivpnTunnel drives the official uz_core binary (the Zivpn UDP client,
// shipped in the repository bundle as bin/armv7/zivpn) exactly like the
// proven reference implementation:
//
//	uz -s <obfs> --config '<inline-json>'
//
// Per port range (comma-separated, e.g. "6000-19999" or
// "6000-6999,7000-7999") one uz_core process is spawned exposing SOCKS5 on
// 127.0.0.1:<uzPort>; a round-robin TCP load balancer unifies them on the
// tunnel SOCKS port (default 127.0.0.1:10810) used as the device upstream.
//
// The inline client JSON (flat, binary-native):
//
//	{"server":"<ip>:<range>","obfs":"<obfs>","auth":"<password>",
//	 "socks5":{"listen":"127.0.0.1:<uzPort>"},"insecure":true,
//	 "recvwindowconn":65536,"recvwindow":262144,
//	 "disable_mtu_discovery":true,"down_mbps":50,"up_mbps":10}
//
// The server hostname is resolved to an IP before spawning (fallback: the
// hostname itself). The obfs value is hardcoded (DefaultZivpnObfsPassword,
// no UI field).
type ZivpnTunnel struct {
	mu        sync.RWMutex
	config    *config.TunnelConfig
	status    Status
	stats     Stats
	cancel    context.CancelFunc
	startTime time.Time

	procs  []*uzProc
	lbLn   net.Listener
	lbPort int
	lbIdx  atomic.Uint32
}

type uzProc struct {
	cmd     *exec.Cmd
	uzPort  int
	rng     string
	stderr  io.ReadCloser
	started bool
}

// DefaultZivpnObfsPassword is the fixed obfs value hardcoded for the
// Zivpn UDP tunnel (no UI field).
const DefaultZivpnObfsPassword = "hu``hqb`c"

// DefaultZivpnPortRange is used when no range is configured.
const DefaultZivpnPortRange = "6000-19999"

func NewZivpnTunnel(cfg *config.TunnelConfig) *ZivpnTunnel {
	return &ZivpnTunnel{
		config: cfg,
		status: StatusStopped,
		stats:  Stats{},
	}
}

func (t *ZivpnTunnel) ID() string              { return t.config.ID }
func (t *ZivpnTunnel) Name() string            { return t.config.Name }
func (t *ZivpnTunnel) Type() config.TunnelType { return config.TunnelZivpn }

func (t *ZivpnTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *ZivpnTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}

func (t *ZivpnTunnel) Config() *config.TunnelConfig { return t.config }

func (t *ZivpnTunnel) socksPort() int {
	return advInt(t.config.Advanced, "socks_port", DefaultZivpnPort)
}

func (t *ZivpnTunnel) authPassword() string {
	if t.config.Auth.Password != "" {
		return t.config.Auth.Password
	}
	return "zi"
}

// maxUzRanges caps uz_core processes per zivpn profile (one per range).
const maxUzRanges = 16

// normalizePortRanges parses the port field into clean "A-B" ranges:
// "6000-7750,7751-9500" (multi-range, one uz_core process each),
// "6000-19999" (single range) or "5667" (single port). Spaces are
// tolerated, reversed bounds are swapped, duplicates dropped. It errors
// when nothing usable remains, so a typo fails fast with a clear message
// instead of spawning uz_core with a garbage server string.
func normalizePortRanges(pr string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, r := range strings.Split(pr, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		var a, b int
		if strings.Contains(r, "-") {
			parts := strings.SplitN(r, "-", 2)
			var err error
			a, err = strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				continue
			}
			b, err = strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				continue
			}
		} else {
			p, err := strconv.Atoi(r)
			if err != nil {
				continue
			}
			a, b = p, p
		}
		if a < 1 || b < 1 || a > 65535 || b > 65535 {
			continue
		}
		if a > b {
			a, b = b, a
		}
		norm := fmt.Sprintf("%d-%d", a, b)
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid port range in %q (use 6000-19999 or 6000-7750,7751-9500)", pr)
	}
	if len(out) > maxUzRanges {
		return nil, fmt.Errorf("too many port ranges (%d, max %d)", len(out), maxUzRanges)
	}
	return out, nil
}

// portRanges returns the configured ranges (comma-separated supported,
// one uz_core process per range, unified by the round-robin balancer).
func (t *ZivpnTunnel) portRanges() ([]string, error) {
	pr := strings.TrimSpace(t.config.Server.PortRange)
	if pr == "" && t.config.Server.Port != 0 {
		pr = fmt.Sprintf("%d-%d", t.config.Server.Port, t.config.Server.Port)
	}
	if pr == "" {
		pr = DefaultZivpnPortRange
	}
	return normalizePortRanges(pr)
}

// resolveServerIP resolves the server hostname to an IP, falling back to
// the hostname itself when resolution fails.
func (t *ZivpnTunnel) resolveServerIP() string {
	host := strings.TrimSpace(t.config.Server.Host)
	if host == "" {
		return host
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	if addr, err := net.ResolveIPAddr("ip", host); err == nil && addr != nil {
		return addr.String()
	}
	return host
}

// pickFreePort asks the kernel for a free loopback TCP port (bind :0),
// so every session gets fresh uz listener ports: no stale-port clashes on
// immediate reconnect, no collision between parallel tunnels.
func pickFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("not a tcp addr")
	}
	return addr.Port, nil
}
func buildUzConfig(ip, portRange, password, obfs string, uzPort int) (string, error) {
	doc := map[string]interface{}{
		"server":                fmt.Sprintf("%s:%s", ip, portRange),
		"obfs":                  obfs,
		"auth":                  password,
		"socks5":                map[string]interface{}{"listen": fmt.Sprintf("127.0.0.1:%d", uzPort)},
		"insecure":              true,
		"recvwindowconn":        65536,
		"recvwindow":            262144,
		"disable_mtu_discovery": true,
		"down_mbps":             50,
		"up_mbps":               10,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (t *ZivpnTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	Tracef("[zivpn] Start() begin status=%s name=%q", t.status, t.config.Name)

	if t.status == StatusRunning {
		Tracef("[zivpn] already running, skip")
		return nil
	}
	if strings.TrimSpace(t.config.Server.Host) == "" {
		Tracef("[zivpn] ERROR: server host empty")
		return fmt.Errorf("zivpn server host is required (server.host)")
	}

	t.status = StatusStarting
	t.setError("")
	// Drop any stale live-port entry immediately: a previous session's
	// dead port must never be dialed while this start is in flight.
	ClearLiveSocksAddr(t.config.ID)

	ctx, t.cancel = context.WithCancel(ctx)

	Tracef("[zivpn] BinDir=%q BinNames=%v", BinDir, BinNames)
	bin := LookupBin(BinDir, BinZivpn)
	Tracef("[zivpn] resolved binary=%q", bin)
	basePort := t.socksPort()
	ranges, err := t.portRanges()
	if err != nil {
		Tracef("[zivpn] ERROR: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	ip := t.resolveServerIP()
	password := t.authPassword()
	Tracef("[zivpn] basePort=%d ranges=%v ip=%q password=%q", basePort, ranges, ip, password)

	// HOME/TMPDIR must be writable; nativeLibraryDir is read-only.
	workDir := os.TempDir()
	homeDir := os.TempDir()

	procs := make([]*uzProc, 0, len(ranges))
	for i, rng := range ranges {
		// Fresh random listener port per session: a previous session's
		// sockets can never collide, even on immediate reconnect.
		uzPort, err := pickFreePort()
		if err != nil {
			Tracef("[zivpn][%d] pickFreePort failed, fallback: %v", i, err)
			uzPort = basePort + 1 + i
		}
		// A previous session may still be releasing a port on an
		// immediate reconnect: wait for it instead of failing.
		if err := waitPortFree(uzPort, 4*time.Second); err != nil {
			Tracef("[zivpn][%d] %v", i, err)
			t.killProcsLocked(procs)
			t.status = StatusError
			t.setError(err.Error())
			return err
		}
		cfgJSON, err := buildUzConfig(ip, rng, password, DefaultZivpnObfsPassword, uzPort)
		if err != nil {
			Tracef("[zivpn] buildUzConfig error: %v", err)
			t.killProcsLocked(procs)
			t.status = StatusError
			t.setError(err.Error())
			return err
		}
		Tracef("[zivpn][%d] cfgJSON=%s", i, cfgJSON)
		Tracef("[zivpn][%d] cmd=%q -s %q --config ...", i, bin, DefaultZivpnObfsPassword)

		cmd := exec.CommandContext(ctx, bin, "-s", DefaultZivpnObfsPassword, "--config", cfgJSON)
		cmd.Dir = workDir
		cmd.Env = append(os.Environ(),
			"LD_LIBRARY_PATH="+BinDir,
			"HOME="+homeDir,
			"TMPDIR="+homeDir,
		)
		stderr, err := cmd.StderrPipe()
		if err != nil {
			t.killProcsLocked(procs)
			t.status = StatusError
			t.setError(err.Error())
			return err
		}
		cmd.Stdout = nil

		if err := cmd.Start(); err != nil {
			Tracef("[zivpn][%d] exec start ERROR: %v", i, err)
			t.killProcsLocked(procs)
			t.status = StatusError
			t.setError(fmt.Sprintf("zivpn start failed: %v", err))
			return fmt.Errorf("failed to start zivpn (uz_core): %w", err)
		}
		Tracef("[zivpn][%d] process started pid=%d", i, cmd.Process.Pid)

		up := &uzProc{cmd: cmd, uzPort: uzPort, rng: rng, stderr: stderr}
		procs = append(procs, up)
		go t.watchOutput(up)

		// Readiness: uz exposes its SOCKS port (5s budget, like reference).
		if err := waitForTCP(fmt.Sprintf("127.0.0.1:%d", uzPort), 5*time.Second); err != nil {
			Tracef("[zivpn][%d] SOCKS %d NOT ready: %v", i, uzPort, err)
			t.killProcsLocked(procs)
			t.status = StatusError
			t.setError(fmt.Sprintf("zivpn range %s not ready: %v", rng, err))
			return fmt.Errorf("zivpn range %s not ready: %w", rng, err)
		}
		Tracef("[zivpn][%d] SOCKS %d ready", i, uzPort)
		up.started = true
	}

	// Round-robin balancer unifying the uz SOCKS endpoints. The LB port is
	// fresh per session (never the fixed default): a previous session's
	// listener — still draining after a slow teardown, or leaked by a
	// wedged one — can never block a reconnect. On collision, repick a
	// new random port instead of failing the session.
	var ln net.Listener
	lbPort := 0
	for attempt := 1; attempt <= 3; attempt++ {
		p, err := pickFreePort()
		if err != nil {
			Tracef("[zivpn] pickFreePort for LB failed: %v", err)
			p = basePort + attempt
		}
		if err := waitPortFree(p, 2*time.Second); err != nil {
			Tracef("[zivpn] LB port %d busy, repicking (attempt %d/3)", p, attempt)
			continue
		}
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			Tracef("[zivpn] LB listen %d failed: %v (attempt %d/3)", p, err, attempt)
			continue
		}
		lbPort = p
		break
	}
	if ln == nil {
		err := fmt.Errorf("zivpn balancer: no free port after 3 attempts")
		Tracef("[zivpn] %v", err)
		t.killProcsLocked(procs)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	Tracef("[zivpn] LB listening on 127.0.0.1:%d", lbPort)
	t.procs = procs
	t.lbLn = ln
	t.lbPort = lbPort
	SetLiveSocksAddr(t.config.ID, fmt.Sprintf("127.0.0.1:%d", lbPort))
	go t.serveBalancer(ctx, ln)

	// Balancer readiness probe.
	if err := waitForTCP(fmt.Sprintf("127.0.0.1:%d", lbPort), 3*time.Second); err != nil {
		t.killProcsLocked(procs)
		ln.Close()
		t.lbLn = nil
		t.procs = nil
		t.lbPort = 0
		ClearLiveSocksAddr(t.config.ID)
		t.status = StatusError
		t.setError(fmt.Sprintf("zivpn balancer not ready: %v", err))
		return fmt.Errorf("zivpn balancer not ready: %w", err)
	}

	t.startTime = time.Now()
	t.status = StatusRunning

	go t.monitorProcs()

	return nil
}

// serveBalancer round-robins TCP connections over the uz upstreams.
func (t *ZivpnTunnel) serveBalancer(ctx context.Context, ln net.Listener) {
	for {
		client, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				// Listener closed on Stop.
				if t.Status() != StatusRunning {
					return
				}
				continue
			}
		}
		go t.relayClient(client)
	}
}

func (t *ZivpnTunnel) relayClient(client net.Conn) {
	t.mu.RLock()
	procs := append([]*uzProc(nil), t.procs...)
	t.mu.RUnlock()

	if len(procs) == 0 {
		Tracef("[zivpn][lb] no upstreams, dropping client")
		client.Close()
		return
	}
	idx := int(t.lbIdx.Add(1)-1) % len(procs)
	up := procs[idx]

	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", up.uzPort), 5*time.Second)
	if err != nil {
		Tracef("[zivpn][lb] upstream 127.0.0.1:%d dial failed: %v", up.uzPort, err)
		client.Close()
		return
	}
	if c, ok := client.(*net.TCPConn); ok {
		c.SetNoDelay(true)
	}
	if c, ok := upstream.(*net.TCPConn); ok {
		c.SetNoDelay(true)
	}

	done := make(chan struct{}, 2)
	started := time.Now()
	var upBytes, downBytes int64
	var upErr, downErr error
	go func() {
		var n int64
		n, upErr = io.Copy(upstream, client)
		upBytes = n
		done <- struct{}{}
	}()
	go func() {
		var n int64
		n, downErr = io.Copy(client, upstream)
		downBytes = n
		done <- struct{}{}
	}()
	<-done
	// Half-close dance instead of a brutal full close, so neither side
	// observes an RST while data may still be in flight.
	closeWrite(client)
	closeWrite(upstream)
	<-done
	client.Close()
	upstream.Close()
	if upErr != nil || downErr != nil {
		Tracef("[zivpn][lb] relay uz:%d up=%d down=%d upErr=%v downErr=%v in %s",
			up.uzPort, upBytes, downBytes, upErr, downErr,
			time.Since(started).Truncate(time.Millisecond))
	} else {
		Tracef("[zivpn][lb] relay uz:%d up=%d down=%d in %s",
			up.uzPort, upBytes, downBytes,
			time.Since(started).Truncate(time.Millisecond))
	}
}

// watchOutput logs every uz process output line (maximal detail).
func (t *ZivpnTunnel) watchOutput(up *uzProc) {
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 1024)
	for {
		n, err := up.stderr.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				i := indexNewline(buf)
				if i < 0 {
					if len(buf) > 65536 {
						buf = buf[len(buf)-4096:]
					}
					break
				}
				line := strings.TrimSpace(string(buf[:i]))
				buf = buf[i+1:]
				if line != "" {
					Tracef("[zivpn][out:%s] %s", up.rng, line)
					lower := strings.ToLower(line)
					if strings.Contains(lower, "error") || strings.Contains(lower, "fail") ||
						strings.Contains(lower, "exception") || strings.Contains(lower, "refused") {
						t.mu.Lock()
						if t.status == StatusRunning {
							t.setError(fmt.Sprintf("zivpn [%s]: %s", up.rng, line))
						}
						t.mu.Unlock()
					}
				}
			}
		}
		if err != nil {
			Tracef("[zivpn][out:%s] stream closed: %v", up.rng, err)
			return
		}
	}
}

func indexNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}

func (t *ZivpnTunnel) killProcsLocked(procs []*uzProc) {
	for _, up := range procs {
		if up.cmd != nil && up.cmd.Process != nil {
			_ = up.cmd.Process.Kill()
			// Reap the zombie so kernel sockets are fully released
			// before any immediate reconnect rebinds the ports.
			done := make(chan struct{})
			go func() {
				_ = up.cmd.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// waitPortFree waits until nothing listens on 127.0.0.1:port (a previous
// session shutting down). Without this, an immediate reconnect can race
// the dying processes still holding uz/LB ports.
func waitPortFree(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err != nil {
			return nil // nobody listening: free
		}
		conn.Close()
		if time.Now().After(deadline) {
			return fmt.Errorf("port %d still busy", port)
		}
		Tracef("[zivpn] port %d busy, waiting for previous session...", port)
		time.Sleep(250 * time.Millisecond)
	}
}

func (t *ZivpnTunnel) monitorProcs() {
	for _, up := range t.procs {
		if up.cmd != nil {
			err := up.cmd.Wait()
			Tracef("[zivpn][mon:%s] process exited: %v", up.rng, err)
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusRunning {
		t.status = StatusError
		if t.stats.LastError == "" {
			t.setError("zivpn process exited")
		}
	}
}

func (t *ZivpnTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}

	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.lbLn != nil {
		t.lbLn.Close()
		t.lbLn = nil
	}
	t.lbPort = 0
	ClearLiveSocksAddr(t.config.ID)
	t.killProcsLocked(t.procs)
	t.procs = nil

	t.status = StatusStopped
	return nil
}

func (t *ZivpnTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *ZivpnTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
