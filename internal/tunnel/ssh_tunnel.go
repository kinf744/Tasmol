package tunnel

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"vpn-app/internal/config"
)

type SSHTunnel struct {
	mu          sync.RWMutex
	config      *config.TunnelConfig
	status      Status
	stats       Stats
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	startTime   time.Time
	pickedSocks int
}

func NewSSHTunnel(cfg *config.TunnelConfig) *SSHTunnel {
	return &SSHTunnel{
		config: cfg,
		status: StatusStopped,
		stats:  Stats{},
	}
}

func (t *SSHTunnel) ID() string              { return t.config.ID }
func (t *SSHTunnel) Name() string            { return t.config.Name }
func (t *SSHTunnel) Type() config.TunnelType { return config.TunnelSSH }

func (t *SSHTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *SSHTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}

func (t *SSHTunnel) Config() *config.TunnelConfig { return t.config }

// redactSSHArgs masks "-i <key>" values (key material, not a path) for logs.
func redactSSHArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == "-i" {
			out[i+1] = "<key-material-redacted>"
		}
	}
	return out
}

func (t *SSHTunnel) socksPort() int {
	if t.pickedSocks > 0 {
		return t.pickedSocks
	}
	return advInt(t.config.Advanced, "socks_port", 10801)
}

func (t *SSHTunnel) buildArgs() []string {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=10",
		"-N",
		"-T",
		"-D", fmt.Sprintf("127.0.0.1:%d", t.socksPort()),
	}

	if t.config.Auth.PrivateKey != "" {
		args = append(args, "-i", t.config.Auth.PrivateKey)
	}

	if t.config.Server.Port != 0 {
		args = append(args, "-p", fmt.Sprintf("%d", t.config.Server.Port))
	}

	userHost := fmt.Sprintf("%s@%s", t.config.Auth.Username, t.config.Server.Host)
	args = append(args, userHost)

	return args
}

func (t *SSHTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	Tracef("[ssh-proc] Start() begin status=%s name=%q id=%s", t.status, t.config.Name, t.config.ID)

	if t.status == StatusRunning {
		Tracef("[ssh-proc] already running, skip")
		return nil
	}
	Tracef("[ssh-proc] inputs host=%q port=%d user=%q keySet=%v passwordSet=%v socksPort=%d",
		t.config.Server.Host, t.config.Server.Port, t.config.Auth.Username,
		t.config.Auth.PrivateKey != "", t.config.Auth.Password != "",
		advInt(t.config.Advanced, "socks_port", 10801))
	if t.config.Server.Host == "" || t.config.Auth.Username == "" {
		Errorf("ssh-proc", "host or username empty")
		return fmt.Errorf("ssh: server.host and auth.username are required")
	}
	if t.config.Auth.PrivateKey == "" && t.config.Auth.Password != "" {
		Warnf("ssh-proc", "password auth with the openssh binary has no TTY: "+
			"ssh will block on a password prompt unless key auth is used")
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	// Fresh random SOCKS port per session (override respected).
	ClearLiveSocksAddr(t.config.ID)
	_, socksPort, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Errorf("ssh-proc", "socks port: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.pickedSocks = socksPort
	Tracef("[ssh-proc] SOCKS picked 127.0.0.1:%d", socksPort)

	args := t.buildArgs()
	Tracef("[ssh-proc] BinDir=%q BinNames=%v", BinDir, BinNames)
	bin := LookupBin(BinDir, BinSSH)
	Tracef("[ssh-proc] binary=%q args=%q", bin, redactSSHArgs(args))

	t.cmd = exec.CommandContext(ctx, bin, args...)

	if err := t.cmd.Start(); err != nil {
		Errorf("ssh-proc", "process start: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("failed to start SSH: %w", err)
	}
	Connf("ssh-proc", "process started pid=%d, RUNNING name=%q", t.cmd.Process.Pid, t.config.Name)

	t.startTime = time.Now()
	t.status = StatusRunning

	go t.monitorProcess()

	return nil
}

func (t *SSHTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}

	Tracef("[ssh-proc] Stop() name=%q", t.config.Name)
	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
		Tracef("[ssh-proc] process reaped")
	}

	t.pickedSocks = 0
	ClearLiveSocksAddr(t.config.ID)
	t.status = StatusStopped
	return nil
}

func (t *SSHTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *SSHTunnel) monitorProcess() {
	err := t.cmd.Wait()
	Tracef("[ssh-proc] process exited: %v", err)
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		t.status = StatusError
		if err != nil {
			t.setError(err.Error())
		}
	}
}

func (t *SSHTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
