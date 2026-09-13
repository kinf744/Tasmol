package tunnel

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"vpn-app/internal/config"
)

type ZivpnTunnel struct {
	mu        sync.RWMutex
	config    *config.TunnelConfig
	status    Status
	stats     Stats
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	startTime time.Time
}

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

func (t *ZivpnTunnel) buildArgs() []string {
	args := []string{
		"connect",
		"--server", t.config.Server.Host,
		"--port", fmt.Sprintf("%d", t.config.Server.Port),
	}

	if t.config.Auth.UUID != "" {
		args = append(args, "--uuid", t.config.Auth.UUID)
	}

	if t.config.Auth.Password != "" {
		args = append(args, "--password", t.config.Auth.Password)
	}

	if t.config.Transport.Network != "" {
		args = append(args, "--network", t.config.Transport.Network)
	} else {
		args = append(args, "--network", "udp")
	}

	if t.config.Transport.Security != "" {
		args = append(args, "--security", t.config.Transport.Security)
	}

	if t.config.Transport.Obfs != "" {
		args = append(args, "--obfs", t.config.Transport.Obfs)
	} else {
		args = append(args, "--obfs", "plain")
	}

	if t.config.Transport.ObfsParam != "" {
		args = append(args, "--obfs-param", t.config.Transport.ObfsParam)
	}

	if t.config.Server.SNI != "" {
		args = append(args, "--sni", t.config.Server.SNI)
	}

	if t.config.Server.PublicKey != "" {
		args = append(args, "--pubkey", t.config.Server.PublicKey)
	}

	if t.config.Server.ShortID != "" {
		args = append(args, "--short-id", t.config.Server.ShortID)
	}

	args = append(args, "--log-level", "info")

	return args
}

func (t *ZivpnTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)
	args := t.buildArgs()
	t.cmd = exec.CommandContext(ctx, "zivpn", args...)

	if err := t.cmd.Start(); err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("failed to start Zivpn: %w", err)
	}

	t.startTime = time.Now()
	t.status = StatusRunning

	go t.monitorProcess()

	return nil
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

	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}

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

func (t *ZivpnTunnel) monitorProcess() {
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

func (t *ZivpnTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
