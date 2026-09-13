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
	mu        sync.RWMutex
	config    *config.TunnelConfig
	status    Status
	stats     Stats
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	startTime time.Time
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

func (t *SSHTunnel) buildArgs() []string {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=10",
		"-N",
		"-T",
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

	if t.status == StatusRunning {
		return nil
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	binPath := "ssh"
	args := t.buildArgs()

	t.cmd = exec.CommandContext(ctx, binPath, args...)

	if err := t.cmd.Start(); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("failed to start SSH: %w", err)
	}

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

	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}

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
