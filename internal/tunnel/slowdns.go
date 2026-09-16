package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
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

// cleanDnsttKey strips copy-paste debris (spaces, newlines, quotes,
// parens, shell metachars) from the dnstt server public key. A pasted key
// with stray whitespace makes dnstt fail cryptically.
func cleanDnsttKey(key string) string {
	for _, r := range []string{" ", "\n", "\r", "\t", "(", ")", "'", "\"", "`", ";", "&", "|", "$"} {
		key = strings.ReplaceAll(key, r, "")
	}
	return key
}

// checkResolver rejects malformed resolvers (e.g. "8.8.8.8:53tomp" from a
// mistyped field) with a clear error instead of a 20s forward timeout.
func checkResolver(resolver string) error {
	h, p, err := net.SplitHostPort(strings.TrimSpace(resolver))
	if err != nil || h == "" {
		return fmt.Errorf("invalid dns resolver %q (want host:port like 8.8.8.8:53)", resolver)
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid dns resolver %q (want host:port like 8.8.8.8:53)", resolver)
	}
	return nil
}
// DnsttArgs builds the official dnstt-client command line.
func DnsttArgs(cfg *config.TunnelConfig, fwdPort int) []string {
	return []string{
		"-udp", DnsttResolver(cfg),
		"-pubkey", cleanDnsttKey(strings.TrimSpace(DnsttPubKey(cfg))),
		DnsttDomain(cfg),
		fmt.Sprintf("127.0.0.1:%d", fwdPort),
	}
}

// StartDnstt validates the SlowDNS settings, starts dnstt-client, streams
// its output to the activity log and blocks until the local forward port
// answers. Call it WITHOUT holding the tunnel mutex (it may wait ~20s).
func StartDnstt(ctx context.Context, cfg *config.TunnelConfig, fwdPort int) (*exec.Cmd, error) {
	Journalf("slowdns", "dnstt ns=%q resolver=%q key=%d chars",
		DnsttDomain(cfg), DnsttResolver(cfg), len(strings.TrimSpace(DnsttPubKey(cfg))))
	if DnsttDomain(cfg) == "" {
		Errorf("slowdns", "nameserver domain empty")
		return nil, fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if DnsttPubKey(cfg) == "" {
		Errorf("slowdns", "public key empty")
		return nil, fmt.Errorf("slowdns server public key is required (server.public_key)")
	}
	if err := checkResolver(DnsttResolver(cfg)); err != nil {
		Errorf("slowdns", "%v", err)
		return nil, err
	}

	Tracef("[slowdns] BinDir=%q BinNames=%v", BinDir, BinNames)
	bin := LookupBin(BinDir, BinSlowDNS)
	args := DnsttArgs(cfg, fwdPort)
	Tracef("[slowdns] binary=%q args=-udp %s -pubkeyLen=%d %s 127.0.0.1:%d",
		bin, DnsttResolver(cfg), len(cleanDnsttKey(DnsttPubKey(cfg))), DnsttDomain(cfg), fwdPort)
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		Errorf("slowdns", "stdout pipe: %v", err)
		return nil, fmt.Errorf("slowdns stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		Errorf("slowdns", "stderr pipe: %v", err)
		return nil, fmt.Errorf("slowdns stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		Errorf("slowdns", "process start: %v", err)
		return nil, fmt.Errorf("failed to start SlowDNS (dnstt-client): %w", err)
	}
	Tracef("[slowdns] process started pid=%d", cmd.Process.Pid)
	go PipeLinesToLog(stdout, "[slowdns][out]")
	go PipeLinesToLog(stderr, "[slowdns][err]")

	if err := waitForTCPctx(ctx, fmt.Sprintf("127.0.0.1:%d", fwdPort), 20*time.Second); err != nil {
		Errorf("slowdns", "forward not ready, killing pid=%d: %v", cmd.Process.Pid, err)
		cmd.Process.Kill()
		return nil, fmt.Errorf("slowdns forward not ready: %w", err)
	}
	Journalf("slowdns", "forward 127.0.0.1:%d ready", fwdPort)
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
