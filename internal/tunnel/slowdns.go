package tunnel

import (
	"context"
	"fmt"
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

// DnsttArgs builds the official dnstt-client command line.
func DnsttArgs(cfg *config.TunnelConfig, fwdPort int) []string {
	return []string{
		"-udp", DnsttResolver(cfg),
		"-pubkey", cfg.Server.PublicKey,
		DnsttDomain(cfg),
		fmt.Sprintf("127.0.0.1:%d", fwdPort),
	}
}

// StartDnstt validates the SlowDNS settings, starts dnstt-client and blocks
// until the local forward port answers. Call it WITHOUT holding the tunnel
// mutex (it may wait up to ~20s).
func StartDnstt(ctx context.Context, cfg *config.TunnelConfig, fwdPort int) (*exec.Cmd, error) {
	if DnsttDomain(cfg) == "" {
		return nil, fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if cfg.Server.PublicKey == "" {
		return nil, fmt.Errorf("slowdns server public key is required (server.public_key)")
	}

	cmd := exec.CommandContext(ctx, LookupBin(BinDir, BinSlowDNS), DnsttArgs(cfg, fwdPort)...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start SlowDNS (dnstt-client): %w", err)
	}

	if err := waitForTCP(fmt.Sprintf("127.0.0.1:%d", fwdPort), 20*time.Second); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("slowdns forward not ready: %w", err)
	}
	return cmd, nil
}
