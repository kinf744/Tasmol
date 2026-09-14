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
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"vpn-app/internal/config"
)

// This file implements SSH without the external openssh binary, for
// platforms where it cannot be executed (Android APK). It uses
// golang.org/x/crypto/ssh plus a minimal embedded SOCKS5 CONNECT server.
// Host-key checking mirrors the process implementation
// (StrictHostKeyChecking=no).

// sshDial opens an SSH client connection from a tunnel config. When
// cfg.SSH.Proxy ("ip:port") is set, SSH is reached through an HTTP CONNECT
// hop carrying cfg.SSH.Payload (see dialViaProxy).
func sshDial(cfg *config.TunnelConfig, addr string) (*ssh.Client, error) {
	auth := make([]ssh.AuthMethod, 0, 2)
	if cfg.Auth.Password != "" {
		auth = append(auth, ssh.Password(cfg.Auth.Password))
	}
	if cfg.Auth.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if cfg.Auth.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cfg.Auth.PrivateKey), []byte(cfg.Auth.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.Auth.PrivateKey))
		}
		if err == nil {
			auth = append(auth, ssh.PublicKeys(signer))
		}
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("ssh: no auth method (need auth.password or auth.private_key)")
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.Auth.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	if strings.TrimSpace(cfg.SSH.Proxy) != "" {
		conn, err := dialViaProxy(cfg.SSH.Proxy, addr, cfg.SSH.Payload)
		if err != nil {
			return nil, fmt.Errorf("ssh proxy hop: %w", err)
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return ssh.NewClient(c, chans, reqs), nil
	}
	return ssh.Dial("tcp", addr, sshCfg)
}

// renderPayload expands a payload template: [crlf]/[lf]/[host]/[port] tokens
// plus [proxy_host]/[proxy_port], then normalizes line endings to CRLF.
func renderPayload(tpl, host, port, proxyHost, proxyPort string) string {
	p := tpl
	p = strings.ReplaceAll(p, "[crlf]", "\r\n")
	p = strings.ReplaceAll(p, "[CRLF]", "\r\n")
	p = strings.ReplaceAll(p, "[lf]", "\n")
	p = strings.ReplaceAll(p, "[LF]", "\n")
	p = strings.ReplaceAll(p, "[host]", host)
	p = strings.ReplaceAll(p, "[port]", port)
	p = strings.ReplaceAll(p, "[proxy_host]", proxyHost)
	p = strings.ReplaceAll(p, "[proxy_port]", proxyPort)
	// Normalize every line ending to CRLF.
	p = strings.ReplaceAll(p, "\r\n", "\n")
	lines := strings.Split(p, "\n")
	return strings.Join(lines, "\r\n")
}

// dialViaProxy opens a TCP connection to an HTTP proxy and issues a CONNECT
// request (with the optional custom payload) towards addr.
func dialViaProxy(proxyAddr, addr, payloadTpl string) (net.Conn, error) {
	proxyHost, _, err := splitProxyAddr(proxyAddr)
	if err != nil {
		return nil, err
	}
	host, port, err := splitProxyAddr(addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}

	var req strings.Builder
	req.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
	req.WriteString("Host: " + addr + "\r\n")
	if strings.TrimSpace(payloadTpl) != "" {
		body := renderPayload(payloadTpl, host, port, proxyHost, portOf(proxyAddr))
		if body != "" {
			if !strings.HasSuffix(body, "\r\n") {
				body += "\r\n"
			}
			req.WriteString(body)
		}
	}
	req.WriteString("\r\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy write: %w", err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy read: %w", err)
	}
	if !strings.Contains(status, " 200") {
		conn.Close()
		return nil, fmt.Errorf("proxy refused: %s", strings.TrimSpace(status))
	}
	// Consume remaining header lines.
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	// Hand the (possibly buffered) connection to the SSH handshake. The
	// buffered reader may already hold handshake bytes, so wrap it.
	if reader.Buffered() > 0 {
		conn = &bufferedConn{Conn: conn, r: reader}
	} else if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// bufferedConn replays bytes already buffered before delegating to Conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func splitProxyAddr(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" || port == "" {
		return "", "", fmt.Errorf("invalid ip:port %q (expected proxy_ip:port)", addr)
	}
	return host, port, nil
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	return port
}

// serveSocks5 runs a minimal SOCKS5 server (CONNECT, no auth) on ln; every
// connection is forwarded through sshClient. It stops when ctx is done.
func serveSocks5(ctx context.Context, ln net.Listener, sshClient *ssh.Client) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handleSocks5(conn, sshClient)
	}
}

func handleSocks5(conn net.Conn, sshClient *ssh.Client) {
	defer conn.Close()

	// Greeting: VER NMETHODS METHODS.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// No-auth accepted.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP ADDR PORT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 { // CONNECT only
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, d); err != nil {
			return
		}
		host = string(d)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	remote, err := sshClient.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Success reply (bound address zeroed).
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	relayTCP(conn, remote)
}

// ---------------------------------------------------------------------------
// NativeSSHTunnel: direct SSH + embedded SOCKS5 (mobile replacement for the
// process-based SSHTunnel).
// ---------------------------------------------------------------------------

type NativeSSHTunnel struct {
	mu        sync.RWMutex
	config    *config.TunnelConfig
	status    Status
	stats     Stats
	client    *ssh.Client
	ln        net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	startTime time.Time
}

func NewNativeSSHTunnel(cfg *config.TunnelConfig) *NativeSSHTunnel {
	return &NativeSSHTunnel{config: cfg, status: StatusStopped}
}

func (t *NativeSSHTunnel) ID() string              { return t.config.ID }
func (t *NativeSSHTunnel) Name() string            { return t.config.Name }
func (t *NativeSSHTunnel) Type() config.TunnelType { return config.TunnelSSH }
func (t *NativeSSHTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}
func (t *NativeSSHTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}
func (t *NativeSSHTunnel) Config() *config.TunnelConfig { return t.config }

func (t *NativeSSHTunnel) socksAddr() string { return SocksAddr(t.config) }

func (t *NativeSSHTunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusRunning {
		return nil
	}
	if t.config.Server.Host == "" || t.config.Auth.Username == "" {
		return fmt.Errorf("ssh: server.host and auth.username are required")
	}

	t.status = StatusStarting
	t.setError("")

	port := t.config.Server.Port
	if port == 0 {
		port = 22
	}
	client, err := sshDial(t.config, net.JoinHostPort(t.config.Server.Host, strconv.Itoa(port)))
	if err != nil {
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("ssh dial failed: %w", err)
	}

	ln, err := net.Listen("tcp", t.socksAddr())
	if err != nil {
		client.Close()
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("socks listen failed: %w", err)
	}

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.client = client
	t.ln = ln
	serveSocks5(t.ctx, ln, client)

	t.startTime = time.Now()
	t.status = StatusRunning
	go t.monitor()
	return nil
}

func (t *NativeSSHTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}
	t.status = StatusStopping
	if t.cancel != nil {
		t.cancel()
	}
	if t.ln != nil {
		t.ln.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	t.status = StatusStopped
	return nil
}

func (t *NativeSSHTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *NativeSSHTunnel) monitor() {
	t.client.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusRunning {
		t.status = StatusError
		t.setError("ssh connection closed")
	}
}

func (t *NativeSSHTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}

// ---------------------------------------------------------------------------
// NativeSSHSlowDNSTunnel: dnstt binary + native SSH dialed through the local
// forward + embedded SOCKS5 (mobile replacement for SSHSlowDNSTunnel; the
// dnstt binary itself IS bundled in the APK).
// ---------------------------------------------------------------------------

type NativeSSHSlowDNSTunnel struct {
	mu         sync.RWMutex
	config     *config.TunnelConfig
	status     Status
	stats      Stats
	client     *ssh.Client
	ln         net.Listener
	slowdnscmd *exec.Cmd
	ctx        context.Context
	cancel     context.CancelFunc
	startTime  time.Time
}

func NewNativeSSHSlowDNSTunnel(cfg *config.TunnelConfig) *NativeSSHSlowDNSTunnel {
	return &NativeSSHSlowDNSTunnel{config: cfg, status: StatusStopped}
}

func (t *NativeSSHSlowDNSTunnel) ID() string              { return t.config.ID }
func (t *NativeSSHSlowDNSTunnel) Name() string            { return t.config.Name }
func (t *NativeSSHSlowDNSTunnel) Type() config.TunnelType { return config.TunnelSSHSlowDNS }
func (t *NativeSSHSlowDNSTunnel) Status() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}
func (t *NativeSSHSlowDNSTunnel) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.status == StatusRunning {
		t.stats.Uptime = int64(time.Since(t.startTime).Seconds())
	}
	return t.stats
}
func (t *NativeSSHSlowDNSTunnel) Config() *config.TunnelConfig { return t.config }

func (t *NativeSSHSlowDNSTunnel) fwdPort() int { return advInt(t.config.Advanced, "fwd_port", 2222) }
func (t *NativeSSHSlowDNSTunnel) socksAddr() string {
	return SocksAddr(t.config)
}
func (t *NativeSSHSlowDNSTunnel) resolver() string {
	if t.config.Server.DNSResolver != "" {
		return t.config.Server.DNSResolver
	}
	return advStr(t.config.Advanced, "dns_resolver", "8.8.8.8")
}
func (t *NativeSSHSlowDNSTunnel) nsDomain() string {
	if t.config.Server.Nameserver != "" {
		return t.config.Server.Nameserver
	}
	return t.config.Server.Hostname
}

func (t *NativeSSHSlowDNSTunnel) Start(ctx context.Context) error {
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

	slowdnsArgs := []string{
		"-udp", t.resolver() + ":53",
		"-pubkey", t.config.Server.PublicKey,
		t.nsDomain(),
		fmt.Sprintf("127.0.0.1:%d", t.fwdPort()),
	}
	t.slowdnscmd = exec.CommandContext(ctx, LookupBin(BinDir, BinSlowDNS), slowdnsArgs...)
	if err := t.slowdnscmd.Start(); err != nil {
		t.status = StatusError
		t.setError(fmt.Sprintf("SlowDNS start failed: %v", err))
		return fmt.Errorf("failed to start SlowDNS (dnstt-client): %w", err)
	}

	t.mu.Unlock()
	fwdErr := waitForTCP(fmt.Sprintf("127.0.0.1:%d", t.fwdPort()), 20*time.Second)
	sshClient, dialErr := sshDial(t.config, fmt.Sprintf("127.0.0.1:%d", t.fwdPort()))
	t.mu.Lock()

	if fwdErr != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(fmt.Sprintf("SlowDNS forward not ready: %v", fwdErr))
		return fmt.Errorf("slowdns forward not ready: %w", fwdErr)
	}
	if dialErr != nil {
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(dialErr.Error())
		return fmt.Errorf("ssh dial through SlowDNS failed: %w", dialErr)
	}

	ln, err := net.Listen("tcp", t.socksAddr())
	if err != nil {
		sshClient.Close()
		t.slowdnscmd.Process.Kill()
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("socks listen failed: %w", err)
	}

	t.ctx = ctx
	t.client = sshClient
	t.ln = ln
	serveSocks5(t.ctx, ln, sshClient)

	t.startTime = time.Now()
	t.status = StatusRunning
	go t.monitor()
	return nil
}

func (t *NativeSSHSlowDNSTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}
	t.status = StatusStopping
	if t.cancel != nil {
		t.cancel()
	}
	if t.ln != nil {
		t.ln.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	if t.slowdnscmd != nil && t.slowdnscmd.Process != nil {
		t.slowdnscmd.Process.Kill()
		t.slowdnscmd.Wait()
	}
	t.status = StatusStopped
	return nil
}

func (t *NativeSSHSlowDNSTunnel) Restart(ctx context.Context) error {
	if err := t.Stop(ctx); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return t.Start(ctx)
}

func (t *NativeSSHSlowDNSTunnel) monitor() {
	if t.client != nil {
		t.client.Wait()
	}
	if t.slowdnscmd != nil {
		t.slowdnscmd.Wait()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusRunning {
		t.status = StatusError
		t.setError("ssh/slowdns connection closed")
	}
}

func (t *NativeSSHSlowDNSTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
