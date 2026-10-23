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

const (
	DefaultSSHSlowDNSFwdPort  = 2222
	DefaultXraySlowDNSFwdPort = 2224
)

func DnsttForwardPort(cfg *config.TunnelConfig, def int) int {
	return advInt(cfg.Advanced, "fwd_port", def)
}

func DnsttForwardPortLive(cfg *config.TunnelConfig, def int) int {
	if cfg != nil {
		if p := LiveForward(cfg.ID); p > 0 {
			return p
		}
	}
	return DnsttForwardPort(cfg, def)
}

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

func DnsttDomain(cfg *config.TunnelConfig) string {
	if cfg.Server.Nameserver != "" {
		return cfg.Server.Nameserver
	}
	return cfg.Server.Hostname
}

func DnsttPubKey(cfg *config.TunnelConfig) string {
	if v := advStr(cfg.Advanced, "slowdns_pubkey", ""); v != "" {
		return v
	}
	return cfg.Server.PublicKey
}

func cleanDnsttKey(key string) string {
	for _, r := range []string{" ", "\n", "\r", "\t", "(", ")", "'", "\"", "`", ";", "&", "|", "$"} {
		key = strings.ReplaceAll(key, r, "")
	}
	return key
}

func DnsttFlag() string {
	if DnsttUseTCP {
		return "-tcp"
	}
	return "-udp"
}

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

func DnsttArgs(cfg *config.TunnelConfig, fwdPort int) []string {
	useTCP := DnsttUseTCP
	if cfg != nil && cfg.Advanced != nil {
		if v, ok := cfg.Advanced["dnstt_tcp"]; ok {
			switch b := v.(type) {
			case bool:
				useTCP = b
			case string:
				if strings.EqualFold(strings.TrimSpace(b), "tcp") {
					useTCP = true
				} else if strings.EqualFold(strings.TrimSpace(b), "udp") {
					useTCP = false
				}
			}
		}
	}
	flag := "-udp"
	if useTCP {
		flag = "-tcp"
	}
	return []string{
		flag, DnsttResolver(cfg),
		"-pubkey", cleanDnsttKey(strings.TrimSpace(DnsttPubKey(cfg))),
		DnsttDomain(cfg),
		fmt.Sprintf("127.0.0.1:%d", fwdPort),
	}
}

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
	Tracef("[slowdns] binary=%q args=%s %s -pubkeyLen=%d %s 127.0.0.1:%d",
		bin, DnsttFlag(), DnsttResolver(cfg), len(cleanDnsttKey(DnsttPubKey(cfg))), DnsttDomain(cfg), fwdPort)
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
	Tracef("[slowdns] forward 127.0.0.1:%d ready", fwdPort)
	return cmd, nil
}

func PipeLinesToLog(r io.Reader, tag string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		if QuietLog {

			if errorish(line) {
				logLine("warning", tag, "%s", line)
			}
			continue
		}
		Tracef("%s %s", tag, line)
	}
}
