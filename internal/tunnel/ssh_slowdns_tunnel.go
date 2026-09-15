package tunnel

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
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
	mu          sync.RWMutex
	config      *config.TunnelConfig
	status      Status
	stats       Stats
	sshCmd      *exec.Cmd
	slowdnscmd  *exec.Cmd
	cancel      context.CancelFunc
	startTime   time.Time
	pickedSocks int
	pickedFwd   int
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
	if t.pickedFwd > 0 {
		return t.pickedFwd
	}
	return DnsttForwardPort(t.config, DefaultSSHSlowDNSFwdPort)
}

func (t *SSHSlowDNSTunnel) socksPort() int {
	if t.pickedSocks > 0 {
		return t.pickedSocks
	}
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

	Tracef("[ssh-slowdns-proc] Start() begin status=%s name=%q id=%s", t.status, t.config.Name, t.config.ID)

	if t.status == StatusRunning {
		Tracef("[ssh-slowdns-proc] already running, skip")
		return nil
	}

	Tracef("[ssh-slowdns-proc] inputs nsDomain=%q resolver=%q pubkeyLen=%d user=%q fwdPort=%d socksPort=%d",
		t.nsDomain(), t.resolver(), len(strings.TrimSpace(t.config.Server.PublicKey)),
		t.config.Auth.Username, t.fwdPort(), t.socksPort())
	if t.nsDomain() == "" {
		Tracef("[ssh-slowdns-proc] ERROR: nameserver domain empty")
		return fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if t.config.Server.PublicKey == "" {
		Tracef("[ssh-slowdns-proc] ERROR: slowdns public key empty")
		return fmt.Errorf("slowdns server public key is required (server.public_key)")
	}
	if t.config.Auth.Username == "" {
		Tracef("[ssh-slowdns-proc] ERROR: ssh username empty")
		return fmt.Errorf("ssh username is required (auth.username)")
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	// Fresh random forward + SOCKS ports per session (overrides respected).
	ClearLiveForward(t.config.ID)
	ClearLiveSocksAddr(t.config.ID)
	fwd, err := PickLiveForward(t.config, DefaultSSHSlowDNSFwdPort)
	if err != nil {
		Tracef("[ssh-slowdns-proc] ERROR fwd port: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.pickedFwd = fwd
	_, socksPort, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Tracef("[ssh-slowdns-proc] ERROR socks port: %v", err)
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.pickedSocks = socksPort
	Tracef("[ssh-slowdns-proc] picked fwd=:%d socks=127.0.0.1:%d", fwd, socksPort)

	// dnstt first (shared helper with output capture), then SSH through it.
	Tracef("[ssh-slowdns-proc] phase 1/2: starting dnstt forward :%d", t.fwdPort())
	t.mu.Unlock()
	dnsttCmd, err := StartDnstt(ctx, t.config, t.fwdPort())
	t.mu.Lock()

	if err != nil {
		Tracef("[ssh-slowdns-proc] ERROR dnstt phase: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.slowdnscmd = dnsttCmd

	sshArgs := t.buildSSHArgs()
	Tracef("[ssh-slowdns-proc] phase 2/2: ssh binary=%q args=%q",
		LookupBin(BinDir, BinSSH), redactSSHArgs(sshArgs))
	t.sshCmd = exec.CommandContext(ctx, LookupBin(BinDir, BinSSH), sshArgs...)

	if err := t.sshCmd.Start(); err != nil {
		Tracef("[ssh-slowdns-proc] ERROR ssh start: %v", err)
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("SSH start failed: %v", err))
		return fmt.Errorf("failed to start SSH through SlowDNS: %w", err)
	}
	Tracef("[ssh-slowdns-proc] ssh started pid=%d slowdns pid=%d, RUNNING name=%q",
		t.sshCmd.Process.Pid, t.slowdnscmd.Process.Pid, t.config.Name)

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

	Tracef("[ssh-slowdns-proc] Stop() name=%q", t.config.Name)
	t.status = StatusStopping

	if t.cancel != nil {
		t.cancel()
	}

	if t.sshCmd != nil && t.sshCmd.Process != nil {
		t.sshCmd.Process.Kill()
		t.sshCmd.Wait()
		Tracef("[ssh-slowdns-proc] ssh reaped")
	}

	if t.slowdnscmd != nil && t.slowdnscmd.Process != nil {
		t.slowdnscmd.Process.Kill()
		t.slowdnscmd.Wait()
		Tracef("[ssh-slowdns-proc] slowdns reaped")
	}

	t.pickedSocks = 0
	t.pickedFwd = 0
	ClearLiveForward(t.config.ID)
	ClearLiveSocksAddr(t.config.ID)
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
	Tracef("[ssh-slowdns-proc] ssh exited: %v", sshErr)
	slowdnsErr := t.slowdnscmd.Wait()
	Tracef("[ssh-slowdns-proc] slowdns exited: %v", slowdnsErr)

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
