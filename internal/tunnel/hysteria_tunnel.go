package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpn-app/internal/config"
)

// HysteriaTunnel drives the official Hysteria v1.3.5 client binary (shipped
// in the repository bundle as bin/armv7/hysteria, sourced from Picko's
// proven implementation):
//
//	hysteria client --config <file.json>
//
// The client exposes SOCKS5 on 127.0.0.1:<livePort> — picked fresh per
// session like every other tunnel so reconnects never collide.
//
// Profil requis (config): server.host, server.port, auth.password.
// Avancés optionnels: hysteria_obfs (string), up_mbps / down_mbps (int),
// port_range (string "5000-6000" ou "443,5000-6000" — port hopping).
type HysteriaTunnel struct {
	mu        sync.RWMutex
	config    *config.TunnelConfig
	status    Status
	stats     Stats
	cancel    context.CancelFunc
	startTime time.Time

	cmd       *exec.Cmd
	cfgPath   string
	socksAddr string
}

func NewHysteriaTunnel(cfg *config.TunnelConfig) *HysteriaTunnel {
	return &HysteriaTunnel{config: cfg, status: StatusStopped}
}

func (t *HysteriaTunnel) ID() string              { return t.config.ID }
func (t *HysteriaTunnel) Name() string            { return t.config.Name }
func (t *HysteriaTunnel) Type() config.TunnelType { return config.TunnelHysteria }

func (t *HysteriaTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *HysteriaTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := t.stats
	if t.status == StatusRunning {
		s.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return s
}

func (t *HysteriaTunnel) Config() *config.TunnelConfig { return t.config }

// resolveServerIP resolves the server hostname to an IP first: the Hysteria
// Go binary cannot rely on Android DNS from a child process (Picko pattern).
func (t *HysteriaTunnel) resolveServerIP() string {
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

// serverSpec builds "ip:port" with optional port hopping
// (advanced.port_range: "5000-6000" -> "ip:443,5000-6000").
func (t *HysteriaTunnel) serverSpec(ip string) string {
	port := strconv.Itoa(t.config.Server.Port)
	rng := ""
	if t.config.Advanced != nil {
		if v, ok := t.config.Advanced["port_range"].(string); ok {
			rng = strings.ReplaceAll(strings.TrimSpace(v), " ", "")
		}
	}
	if rng != "" {
		return fmt.Sprintf("%s:%s,%s", ip, port, rng)
	}
	return fmt.Sprintf("%s:%s", ip, port)
}

// buildHysteriaConfig reproduces Picko's client configuration (Hysteria
// v1.3.5 JSON), with our live SOCKS port and per-profile obfs.
func buildHysteriaConfig(server, sniName, auth, obfs string, up, down, socksPort int) ([]byte, error) {
	doc := map[string]interface{}{
		"server":                server,
		"auth_str":              auth,
		"up_mbps":               up,
		"down_mbps":             down,
		"retry":                 10,
		"retry_interval":        2,
		"handshake_timeout":     10,
		"idle_timeout":          300,
		"hop_interval":          10,
		"server_name":           sniName,
		"insecure":              true,
		"disable_mtu_discovery": false,
		"fast_open":             false,
		"recv_window_conn":      4194304,
		"recv_window":           16777216,
		"socks5": map[string]interface{}{
			"listen":      fmt.Sprintf("127.0.0.1:%d", socksPort),
			"timeout":     300,
			"disable_udp": false,
		},
	}
	if strings.TrimSpace(obfs) != "" {
		doc["obfs"] = strings.TrimSpace(obfs)
	}
	return json.Marshal(doc)
}

func (t *HysteriaTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	Tracef("[hysteria] Start() begin status=%s name=%q", t.status, t.config.Name)

	if t.status == StatusRunning {
		Tracef("[hysteria] already running, skip")
		return nil
	}
	host := strings.TrimSpace(t.config.Server.Host)
	authPass := strings.TrimSpace(t.config.Auth.Password)
	if host == "" || t.config.Server.Port <= 0 || authPass == "" {
		err := fmt.Errorf("hysteria: server.host, server.port et auth.password sont requis")
		Errorf("hysteria", "%v", err)
		return err
	}

	t.status = StatusStarting
	t.setError("")
	ClearLiveSocksAddr(t.config.ID)

	ctx, t.cancel = context.WithCancel(ctx)

	bin := LookupBin(BinDir, BinHysteria)
	ip := t.resolveServerIP()
	server := t.serverSpec(ip)

	// Fresh random socks port per session (même convention que zivpn).
	socksAddr, socksPort, err := PickLiveSocksAddr(t.config)
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	if err := waitPortFreeCtx(ctx, socksPort, 4*time.Second); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	up := advInt(t.config.Advanced, "up_mbps", 10)
	if up < 1 {
		up = 10
	}
	down := advInt(t.config.Advanced, "down_mbps", 50)
	if down < 1 {
		down = 50
	}
	obfs := ""
	if t.config.Advanced != nil {
		if v, ok := t.config.Advanced["hysteria_obfs"].(string); ok {
			obfs = v
		}
	}

	raw, err := buildHysteriaConfig(server, host, authPass, obfs, up, down, socksPort)
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	cfgPath := fmt.Sprintf("%s/hysteria-%s.json", TmpDir, t.config.ID)
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.cfgPath = cfgPath
	t.socksAddr = socksAddr

	Journalf("hysteria", "udp %s (socks %s)", server, socksAddr)

	cmd := exec.CommandContext(ctx, bin, "client", "--config", cfgPath)
	cmd.Dir = TmpDir
	cmd.Env = append(os.Environ(),
		"LD_LIBRARY_PATH="+BinDir,
		"HOME="+TmpDir,
		"TMPDIR="+TmpDir,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.Remove(cfgPath)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.Remove(cfgPath)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	if err := cmd.Start(); err != nil {
		os.Remove(cfgPath)
		t.status = StatusError
		t.setError(fmt.Sprintf("hysteria start failed: %v", err))
		Errorf("hysteria", "exec start failed: %v", err)
		return fmt.Errorf("failed to start hysteria client: %w", err)
	}
	t.cmd = cmd
	Tracef("[hysteria] process started pid=%d", cmd.Process.Pid)
	go PipeLinesToLog(stdout, "[hysteria][out]")
	go PipeLinesToLog(stderr, "[hysteria][err]")
	go t.watchProcess(cmd)

	// Readiness: SOCKS local doit répondre (15 s comme la référence Picko).
	if err := waitForTCPctx(ctx, socksAddr, 15*time.Second); err != nil {
		t.killLocked()
		t.status = StatusError
		t.setError(fmt.Sprintf("hysteria socks not ready: %v", err))
		Errorf("hysteria", "SOCKS %s not ready: %v", socksAddr, err)
		return fmt.Errorf("hysteria socks not ready: %w", err)
	}
	SetLiveSocksAddr(t.config.ID, socksAddr)

	t.startTime = time.Now()
	t.status = StatusRunning
	Tracef("[hysteria] RUNNING name=%q socks=%s", t.config.Name, socksAddr)
	Connf("hysteria", "connecté %s (UDP)", server)
	return nil
}

// watchProcess flips the tunnel to error when the child dies unexpectedly.
func (t *HysteriaTunnel) watchProcess(cmd *exec.Cmd) {
	err := cmd.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cmd != cmd {
		return // arrêt propre (Stop a déjà nettoyé)
	}
	if t.status == StatusRunning || t.status == StatusStarting {
		t.status = StatusError
		t.setError(fmt.Sprintf("hysteria exited: %v", err))
		Errorf("hysteria", "process exited: %v", err)
	}
}

func (t *HysteriaTunnel) killLocked() {
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		_, _ = t.cmd.Process.Wait()
	}
	t.cmd = nil
	if t.cfgPath != "" {
		_ = os.Remove(t.cfgPath)
		t.cfgPath = ""
	}
}

func (t *HysteriaTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}
	t.status = StatusStopping
	if t.cancel != nil {
		t.cancel()
	}
	ClearLiveSocksAddr(t.config.ID)
	t.killLocked()
	t.socksAddr = ""
	t.status = StatusStopped
	return nil
}

func (t *HysteriaTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *HysteriaTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
