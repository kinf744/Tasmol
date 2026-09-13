package tunnel

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"vpn-app/internal/config"
)

type SSHSlowDNSTunnel struct {
	mu           sync.RWMutex
	config       *config.TunnelConfig
	status       Status
	stats        Stats
	sshCmd       *exec.Cmd
	slowdnscmd   *exec.Cmd
	cancel       context.CancelFunc
	startTime    time.Time
	localPort    int
	dnsServer    string
}

func NewSSHSlowDNSTunnel(cfg *config.TunnelConfig) *SSHSlowDNSTunnel {
	return &SSHSlowDNSTunnel{
		config:     cfg,
		status:     StatusStopped,
		stats:      Stats{},
		localPort:  2222,
		dnsServer:  "8.8.8.8",
	}
}

func (t *SSHSlowDNSTunnel) ID() string        { return t.config.ID }
func (t *SSHSlowDNSTunnel) Name() string      { return t.config.Name }
func (t *SSHSlowDNSTunnel) Type() config.TunnelType { return config.TunnelSSHSlowDNS }

func (t *SSHSlowDNSTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *SSHSlowDNSTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}

func (t *SSHSlowDNSTunnel) Config() *config.TunnelConfig { return t.config }

func (t *SSHSlowDNSTunnel) buildSSHArgs() []string {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=10",
		"-N", "-T",
		"-D", fmt.Sprintf("127.0.0.1:%d", t.localPort),
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

func (t *SSHSlowDNSTunnel) buildSlowDNSArgs() []string {
	args := []string{
		"-udp",
		"-listen", fmt.Sprintf("127.0.0.1:%d", t.localPort+1),
		"-dns", t.dnsServer,
		"-pubkey", t.config.Server.PublicKey,
		"-nameserver", t.config.Server.Host,
	}

	if t.config.Server.Port != 0 {
		args = append(args, "-port", fmt.Sprintf("%d", t.config.Server.Port))
	}

	return args
}

func (t *SSHSlowDNSTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	sshArgs := t.buildSSHArgs()
	t.sshCmd = exec.CommandContext(ctx, "ssh", sshArgs...)

	if err := t.sshCmd.Start(); err != nil {
		t.status = StatusError
		t.setError(fmt.Sprintf("SSH start failed: %v", err))
		return fmt.Errorf("failed to start SSH: %w", err)
	}

	time.Sleep(1 * time.Second)

	slowdnsArgs := t.buildSlowDNSArgs()
	t.slowdnscmd = exec.CommandContext(ctx, "slowdns", slowdnsArgs...)

	if err := t.slowdnscmd.Start(); err != nil {
		t.sshCmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("SlowDNS start failed: %v", err))
		return fmt.Errorf("failed to start SlowDNS: %w", err)
	}

	t.startTime = time.Now()
	t.status = StatusRunning

	go t.monitorProcesses()

	return nil
}

func (t *SSHSlowDNSTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}

	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.sshCmd != nil && t.sshCmd.Process != nil {
		t.sshCmd.Process.Kill()
		t.sshCmd.Wait()
	}

	if t.slowdnscmd != nil && t.slowdnscmd.Process != nil {
		t.slowdnscmd.Process.Kill()
		t.slowdnscmd.Wait()
	}

	t.status = StatusStopped
	return nil
}

func (t *SSHSlowDNSTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *SSHSlowDNSTunnel) monitorProcesses() {
	sshErr := t.sshCmd.Wait()
	slowdnsErr := t.slowdnscmd.Wait()

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		t.status = StatusError
		if sshErr != nil {
			t.setError(fmt.Sprintf("SSH: %v", sshErr))
		} else if slowdnsErr != nil {
			t.setError(fmt.Sprintf("SlowDNS: %v", slowdnsErr))
		}
	}
}

func (t *SSHSlowDNSTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}