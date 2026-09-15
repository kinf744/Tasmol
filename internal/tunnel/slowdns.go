package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"vpn-app/internal/config"
)

// Shared dnstt (SlowDNS) helpers used by the ssh_slowdns / xray_slowdns
// tunnels and by the mobile front-end.
//
// Official client: dnstt-client built from OutlineFoundation/dnstt,
// stored in the repository bundle as bin/armv7/slowdns. Invocation:
// slowdns -udp <resolver>:53 -pubkey <hexkey> <ns-domain> 127.0.0.1:<fwdPort>

// Default local forward ports exposed by dnstt-client.
const (
	DefaultSSHSlowDNSFwdPort  = 2222
	DefaultXraySlowDNSFwdPort = 2224
)

// DnsttForwardPort resolves the local dnstt forward port.
func DnsttForwardPort(cfg *config.TunnelConfig, def int) int {
	return advInt(cfg.Advanced, "fwd_port", def)
}

// DnsttForwardPortLive returns the live dnstt forward port of a running
// session, falling back to the static configured/default port.
func DnsttForwardPortLive(cfg *config.TunnelConfig, def int) int {
	if cfg != nil {
		if p := LiveForward(cfg.ID); p > 0 {
			return p
		}
	}
	return DnsttForwardPort(cfg, def)
}

// DnsttResolver resolves the UDP DNS resolver used by dnstt-client as
// "host:port" (e.g. "8.8.8.8:53"). A bare IP gets ":53" appended.
func DnsttResolver(cfg *config.TunnelConfig) string {
	resolver := cfg.Server.DNSResolver
	if resolver == "" {
		resolver = advStr(cfg.Advanced, "dns_resolver", "8.8.8.8:53")
	}
	if resolver == "" {
		resolver = "8.8.8.8:53"
	}
	if !strings.Contains(resolver, ":") {
		resolver += ":53"
	}
	return resolver
}

// DnsttDomain resolves the dnstt zone (nameserver) domain.
func DnsttDomain(cfg *config.TunnelConfig) string {
	if cfg.Server.Nameserver != "" {
		return cfg.Server.Nameserver
	}
	return cfg.Server.Hostname
}

// DnsttPubKey resolves the dnstt server public key (hex). Advanced
// ["slowdns_pubkey"] wins when the same config also carries another key
// (e.g. a Reality public key in server.public_key).
func DnsttPubKey(cfg *config.TunnelConfig) string {
	if v := advStr(cfg.Advanced, "slowdns_pubkey", ""); v != "" {
		return v
	}
	return cfg.Server.PublicKey
}

// DnsttArgs builds the official dnstt-client command line.
func DnsttArgs(cfg *config.TunnelConfig, fwdPort int) []string {
	return []string{
		"-udp", DnsttResolver(cfg),
		"-pubkey", strings.TrimSpace(DnsttPubKey(cfg)),
		DnsttDomain(cfg),
		fmt.Sprintf("127.0.0.1:%d", fwdPort),
	}
}

// StartDnstt validates the SlowDNS settings, starts dnstt-client, streams
// its output to the activity log and blocks until the local forward port
// answers. Call it WITHOUT holding the tunnel mutex (it may wait ~20s).
func StartDnstt(ctx context.Context, cfg *config.TunnelConfig, fwdPort int) (*exec.Cmd, error) {
	Tracef("[slowdns] StartDnstt begin nsDomain=%q resolver=%q pubkeyLen=%d fwdPort=%d",
		DnsttDomain(cfg), DnsttResolver(cfg), len(strings.TrimSpace(DnsttPubKey(cfg))), fwdPort)
	if DnsttDomain(cfg) == "" {
		Tracef("[slowdns] ERROR: nameserver domain empty")
		return nil, fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if DnsttPubKey(cfg) == "" {
		Tracef("[slowdns] ERROR: public key empty")
		return nil, fmt.Errorf("slowdns server public key is required (server.public_key)")
	}

	Tracef("[slowdns] BinDir=%q BinNames=%v", BinDir, BinNames)
	bin := LookupBin(BinDir, BinSlowDNS)
	args := DnsttArgs(cfg, fwdPort)
	Tracef("[slowdns] binary=%q args=-udp %s -pubkey %.12s... %s 127.0.0.1:%d",
		bin, DnsttResolver(cfg), DnsttPubKey(cfg), DnsttDomain(cfg), fwdPort)
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		Tracef("[slowdns] ERROR stdout pipe: %v", err)
		return nil, fmt.Errorf("slowdns stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		Tracef("[slowdns] ERROR stderr pipe: %v", err)
		return nil, fmt.Errorf("slowdns stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		Tracef("[slowdns] ERROR process start: %v", err)
		return nil, fmt.Errorf("failed to start SlowDNS (dnstt-client): %w", err)
	}
	Tracef("[slowdns] process started pid=%d", cmd.Process.Pid)
	go PipeLinesToLog(stdout, "[slowdns][out]")
	go PipeLinesToLog(stderr, "[slowdns][err]")

	if err := waitForTCPctx(ctx, fmt.Sprintf("127.0.0.1:%d", fwdPort), 20*time.Second); err != nil {
		Tracef("[slowdns] forward NOT ready, killing pid=%d: %v", cmd.Process.Pid, err)
		cmd.Process.Kill()
		return nil, fmt.Errorf("slowdns forward not ready: %w", err)
	}
	Tracef("[slowdns] forward 127.0.0.1:%d ready", fwdPort)
	return cmd, nil
}

// PipeLinesToLog streams a child process pipe into the activity log.
func PipeLinesToLog(r io.Reader, tag string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		Tracef("%s %s", tag, sc.Text())
	}
}
