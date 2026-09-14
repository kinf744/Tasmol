package tunnel

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"vpn-app/internal/config"
)

// SSHSlowDNSTunnel chains the official dnstt SlowDNS client with an SSH
// dynamic forward:
//
//	slowdns -udp <resolver>:53 -pubkey <hex> <ns-domain> 127.0.0.1:<fwdPort>
//	ssh -p <fwdPort> -D 127.0.0.1:<socksPort> user@127.0.0.1
//
// The dnstt client exposes the remote SSH service on localhost; SSH then
// connects THROUGH the DNS tunnel. Defaults: fwdPort 2222 (ecosystem
// convention), socksPort 10802, resolver 8.8.8.8. All overridable via the
// tunnel Advanced map ("fwd_port", "socks_port", "dns_resolver").
type SSHSlowDNSTunnel struct {
	mu         sync.RWMutex
	config     *config.TunnelConfig
	status     Status
	stats      Stats
	sshCmd     *exec.Cmd
	slowdnscmd *exec.Cmd
	cancel     context.CancelFunc
	startTime  time.Time
}

func NewSSHSlowDNSTunnel(cfg *config.TunnelConfig) *SSHSlowDNSTunnel {
	return &SSHSlowDNSTunnel{
		config: cfg,
		status: StatusStopped,
		stats:  Stats{},
	}
}

func (t *SSHSlowDNSTunnel) ID() string              { return t.config.ID }
func (t *SSHSlowDNSTunnel) Name() string            { return t.config.Name }
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

func (t *SSHSlowDNSTunnel) fwdPort() int {
	return DnsttForwardPort(t.config, DefaultSSHSlowDNSFwdPort)
}

func (t *SSHSlowDNSTunnel) socksPort() int {
	return advInt(t.config.Advanced, "socks_port", 10802)
}

func (t *SSHSlowDNSTunnel) resolver() string {
	return DnsttResolver(t.config)
}

func (t *SSHSlowDNSTunnel) nsDomain() string {
	return DnsttDomain(t.config)
}

// buildSSHArgs connects SSH through the local dnstt forward and exposes a
// SOCKS5 proxy for the device traffic.
func (t *SSHSlowDNSTunnel) buildSSHArgs() []string {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=15",
		"-N", "-T",
		"-p", fmt.Sprintf("%d", t.fwdPort()),
		"-D", fmt.Sprintf("127.0.0.1:%d", t.socksPort()),
	}

	if t.config.Auth.PrivateKey != "" {
		args = append(args, "-i", t.config.Auth.PrivateKey)
	}

	userHost := fmt.Sprintf("%s@127.0.0.1", t.config.Auth.Username)
	args = append(args, userHost)

	return args
}

func (t *SSHSlowDNSTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}

	if t.nsDomain() == "" {
		return fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if t.config.Server.PublicKey == "" {
		return fmt.Errorf("slowdns server public key is required (server.public_key)")
	}
	if t.config.Auth.Username == "" {
		return fmt.Errorf("ssh username is required (auth.username)")
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	// dnstt first (shared helper with output capture), then SSH through it.
	t.mu.Unlock()
	dnsttCmd, err := StartDnstt(ctx, t.config, t.fwdPort())
	t.mu.Lock()

	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.slowdnscmd = dnsttCmd

	sshArgs := t.buildSSHArgs()
	t.sshCmd = exec.CommandContext(ctx, LookupBin(BinDir, BinSSH), sshArgs...)

	if err := t.sshCmd.Start(); err != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("SSH start failed: %v", err))
		return fmt.Errorf("failed to start SSH through SlowDNS: %w", err)
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
