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
	hasPass := cfg.Auth.Password != ""
	hasKey := strings.TrimSpace(cfg.Auth.PrivateKey) != ""
	hasPhrase := cfg.Auth.Passphrase != ""
	Tracef("[ssh] dial begin addr=%s user=%q passwordSet=%v keySet=%v passphraseSet=%v proxy=%q payloadLen=%d",
		addr, cfg.Auth.Username, hasPass, hasKey, hasPhrase,
		cfg.SSH.Proxy, len(cfg.SSH.Payload))
	auth := make([]ssh.AuthMethod, 0, 2)
	if hasPass {
		auth = append(auth, ssh.Password(cfg.Auth.Password))
	}
	if hasKey {
		var signer ssh.Signer
		var err error
		if hasPhrase {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cfg.Auth.PrivateKey), []byte(cfg.Auth.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.Auth.PrivateKey))
		}
		if err == nil {
			auth = append(auth, ssh.PublicKeys(signer))
			Tracef("[ssh] private key parsed OK")
		} else {
			Tracef("[ssh] ERROR private key unparsable: %v", err)
		}
	}
	if len(auth) == 0 {
		Tracef("[ssh] ERROR: no usable auth method")
		return nil, fmt.Errorf("ssh: no auth method (need auth.password or auth.private_key)")
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.Auth.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	if strings.TrimSpace(cfg.SSH.Proxy) != "" {
		Tracef("[ssh] hop via HTTP proxy %s", cfg.SSH.Proxy)
		conn, err := dialViaProxy(cfg.SSH.Proxy, addr, cfg.SSH.Payload)
		if err != nil {
			Tracef("[ssh] ERROR proxy hop: %v", err)
			return nil, fmt.Errorf("ssh proxy hop: %w", err)
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
		if err != nil {
			Tracef("[ssh] ERROR handshake via proxy: %v", err)
			conn.Close()
			return nil, err
		}
		Tracef("[ssh] handshake OK via proxy")
		return ssh.NewClient(c, chans, reqs), nil
	}
	Tracef("[ssh] direct dial %s ...", addr)
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		Tracef("[ssh] ERROR direct dial/handshake: %v", err)
		return nil, err
	}
	Tracef("[ssh] handshake OK")
	return client, nil
}

// renderPayload expands a payload template like HTTP Injector / HTTP
// Custom: [crlf]/[lf]/[cr]/[host]/[port]/[host_port]/[protocol] tokens plus
// [proxy_host]/[proxy_port]. Line endings are honored EXACTLY ([lf] stays
// a bare LF: some proxies reject forced CRLF). [delay]/[delay_split]
// DPI-evasion timings are stripped (sent continuously) — logged by caller.
func renderPayload(tpl, host, port, proxyHost, proxyPort string) string {
	p := tpl
	p = strings.ReplaceAll(p, "[CRLF]", "\r\n")
	p = strings.ReplaceAll(p, "[crlf]", "\r\n")
	p = strings.ReplaceAll(p, "[LF]", "\n")
	p = strings.ReplaceAll(p, "[lf]", "\n")
	p = strings.ReplaceAll(p, "[CR]", "\r")
	p = strings.ReplaceAll(p, "[cr]", "\r")
	p = strings.ReplaceAll(p, "[host_port]", host+":"+port)
	p = strings.ReplaceAll(p, "[HOST_PORT]", host+":"+port)
	p = strings.ReplaceAll(p, "[host]", host)
	p = strings.ReplaceAll(p, "[HOST]", host)
	p = strings.ReplaceAll(p, "[port]", port)
	p = strings.ReplaceAll(p, "[PORT]", port)
	p = strings.ReplaceAll(p, "[protocol]", "HTTP/1.1")
	p = strings.ReplaceAll(p, "[PROTOCOL]", "HTTP/1.1")
	p = strings.ReplaceAll(p, "[proxy_host]", proxyHost)
	p = strings.ReplaceAll(p, "[proxy_port]", proxyPort)
	// Timing-evasion tokens have no meaning here: strip them instead of
	// sending them literally (the proxy would choke on "[delay_split]").
	p = strings.ReplaceAll(p, "[delay_split]", "")
	p = strings.ReplaceAll(p, "[DELAY_SPLIT]", "")
	p = strings.ReplaceAll(p, "[delay]", "")
	p = strings.ReplaceAll(p, "[DELAY]", "")
	p = strings.ReplaceAll(p, "[netData]", "")
	return p
}

// isFullRequest reports whether a rendered payload already carries its own
// HTTP request line (Injector "custom request" style): prepending another
// CONNECT would glue two requests and hang the proxy silent.
func isFullRequest(body string) bool {
	upper := strings.ToUpper(strings.TrimLeft(body, " \t\r\n"))
	for _, m := range []string{"CONNECT ", "GET ", "POST ", "HEAD ", "OPTIONS ", "PUT ", "DELETE ", "PATCH ", "TRACE "} {
		if strings.HasPrefix(upper, m) {
			return true
		}
	}
	return false
}

// proxyStatusCode extracts the 3-digit code from an HTTP status line
// ("HTTP/1.1 200 OK" -> 200), or 0 when unparsable.
func proxyStatusCode(status string) int {
	parts := strings.Fields(status)
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0
	}
	return code
}

// dialViaProxy opens a TCP connection to an HTTP proxy and issues a CONNECT
// request (with the optional custom payload) towards addr.
func dialViaProxy(proxyAddr, addr, payloadTpl string) (net.Conn, error) {
	Tracef("[ssh] proxy hop: proxy=%s target=%s payloadLen=%d", proxyAddr, addr, len(payloadTpl))
	proxyHost, proxyPort, err := splitProxyAddr(proxyAddr)
	if err != nil {
		Tracef("[ssh] ERROR bad proxy addr: %v", err)
		return nil, err
	}
	host, port, err := splitProxyAddr(addr)
	if err != nil {
		Tracef("[ssh] ERROR bad target addr: %v", err)
		return nil, err
	}
	if proxyHost == host && proxyPort == port {
		Tracef("[ssh] WARNING proxy == target (%s): the proxy would CONNECT to itself; check ssh.proxy vs server host/port", addr)
	}
	if strings.Contains(strings.ToLower(payloadTpl), "[delay") {
		Tracef("[ssh] note: [delay*] timing tokens stripped (sent continuously)")
	}

	conn, err := net.DialTimeout("tcp", proxyHost+":"+proxyPort, 15*time.Second)
	if err != nil {
		Tracef("[ssh] ERROR dial proxy %s:%s: %v (proxy unreachable: wrong IP/port, proxy down, or carrier-filtered)", proxyHost, proxyPort, err)
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}

	var req strings.Builder
	if strings.TrimSpace(payloadTpl) != "" {
		body := renderPayload(payloadTpl, host, port, proxyHost, portOf(proxyAddr))
		if isFullRequest(body) {
			// Injector-style: the payload IS the complete HTTP request
			// (its own CONNECT/GET line). Prepending another CONNECT
			// glues two requests together and the proxy hangs silent.
			Tracef("[ssh] full-request payload, sent as-is (%d bytes)", len(body))
			req.WriteString(body)
			if !strings.HasSuffix(body, "\r\n") {
				req.WriteString("\r\n")
			}
		} else {
			req.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
			req.WriteString("Host: " + addr + "\r\n")
			if body != "" {
				if !strings.HasSuffix(body, "\r\n") {
					body += "\r\n"
				}
				req.WriteString(body)
			}
		}
	} else {
		req.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
		req.WriteString("Host: " + addr + "\r\n")
	}
	req.WriteString("\r\n")

	if lines := strings.Split(req.String(), "\r\n"); len(lines) > 0 {
		Tracef("[ssh] CONNECT request line: %s (+%d header/payload lines)", lines[0], len(lines)-1)
	}
	if _, err := conn.Write([]byte(req.String())); err != nil {
		Tracef("[ssh] ERROR proxy write: %v", err)
		conn.Close()
		return nil, fmt.Errorf("proxy write: %w", err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		Tracef("[ssh] ERROR proxy read: %v", err)
		conn.Close()
		return nil, fmt.Errorf("proxy read: %w", err)
	}
	Tracef("[ssh] proxy status: %s", strings.TrimSpace(status))
	code := proxyStatusCode(status)
	// 2xx = standard success. 101 = the WS-panel convention (EDOZTUNNEL
	// style): "tunnel open, proceed" despite the informational code.
	if !((code >= 200 && code < 300) || code == 101) {
		conn.Close()
		return nil, fmt.Errorf("proxy refused: %s", strings.TrimSpace(status))
	}
	// Consume remaining header lines, tolerantly: quirky proxies may send
	// no terminating blank line — never fail here, the buffered wrapper
	// below replays anything already read.
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	// Hand the (possibly buffered) connection to the SSH handshake. The
	// buffered reader may already hold handshake bytes, so wrap it.
	// The hop deadline is cleared either way: the SSH handshake and the
	// session get the full configured timeouts, not the 3s header budget.
	if reader.Buffered() > 0 {
		conn = &bufferedConn{Conn: conn, r: reader}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
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
	a := strings.TrimSpace(addr)
	// Tolerate pasted URLs ("http://1.2.3.4:8080/path").
	if i := strings.Index(a, "://"); i >= 0 {
		a = a[i+3:]
	}
	if i := strings.Index(a, "/"); i >= 0 {
		a = a[:i]
	}
	host, port, err = net.SplitHostPort(a)
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

// socksPortOf extracts the port from a 127.0.0.1:port endpoint (0 if bad).
func socksPortOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(p)
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

	Tracef("[ssh] Start() begin status=%s name=%q id=%s", t.status, t.config.Name, t.config.ID)

	if t.status == StatusRunning {
		Tracef("[ssh] already running, skip")
		return nil
	}
	Tracef("[ssh] inputs host=%q port=%d user=%q socks=%s proxy=%q",
		t.config.Server.Host, t.config.Server.Port, t.config.Auth.Username,
		t.socksAddr(), t.config.SSH.Proxy)
	if t.config.Server.Host == "" || t.config.Auth.Username == "" {
		Tracef("[ssh] ERROR: host or username empty")
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
		Tracef("[ssh] ERROR sshDial: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("ssh dial failed: %w", err)
	}

	// Fresh random SOCKS port per session (override respected): never
	// reuse, never collide with a draining previous session.
	ClearLiveSocksAddr(t.config.ID)
	socksAddr, _, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Tracef("[ssh] ERROR socks port: %v", err)
		client.Close()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	Tracef("[ssh] SOCKS picked %s", socksAddr)
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		Tracef("[ssh] ERROR socks listen %s: %v", socksAddr, err)
		ClearLiveSocksAddr(t.config.ID)
		client.Close()
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("socks listen failed: %w", err)
	}
	Tracef("[ssh] SOCKS listening on %s", socksAddr)

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.client = client
	t.ln = ln
	serveSocks5(t.ctx, ln, client)

	t.startTime = time.Now()
	t.status = StatusRunning
	Tracef("[ssh] RUNNING name=%q", t.config.Name)
	go t.monitor()
	return nil
}

func (t *NativeSSHTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}
	Tracef("[ssh] Stop() name=%q", t.config.Name)
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
	ClearLiveSocksAddr(t.config.ID)
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
	Tracef("[ssh] connection closed (monitor)")
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

	Tracef("[ssh-slowdns] Start() begin status=%s name=%q id=%s", t.status, t.config.Name, t.config.ID)

	if t.status == StatusRunning {
		Tracef("[ssh-slowdns] already running, skip")
		return nil
	}
	Tracef("[ssh-slowdns] inputs nsDomain=%q resolver=%q pubkeyLen=%d user=%q fwdPort=%d socks=%s",
		t.nsDomain(), t.resolver(), len(strings.TrimSpace(t.config.Server.PublicKey)),
		t.config.Auth.Username, t.fwdPort(), t.socksAddr())
	if t.nsDomain() == "" {
		Tracef("[ssh-slowdns] ERROR: nameserver domain empty")
		return fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if t.config.Server.PublicKey == "" {
		Tracef("[ssh-slowdns] ERROR: slowdns public key empty")
		return fmt.Errorf("slowdns server public key is required (server.public_key)")
	}
	if t.config.Auth.Username == "" {
		Tracef("[ssh-slowdns] ERROR: ssh username empty")
		return fmt.Errorf("ssh username is required (auth.username)")
	}

	t.status = StatusStarting
	t.setError("")

	ctx, t.cancel = context.WithCancel(ctx)

	// Fresh random forward + SOCKS ports per session (overrides
	// respected): two profiles of the same type never share 2222/10802.
	ClearLiveForward(t.config.ID)
	ClearLiveSocksAddr(t.config.ID)
	fwdPort, err := PickLiveForward(t.config, DefaultSSHSlowDNSFwdPort)
	if err != nil {
		Tracef("[ssh-slowdns] ERROR fwd port: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	// dnstt first (shared helper with output capture).
	Tracef("[ssh-slowdns] phase 1/2: starting dnstt forward :%d", fwdPort)
	t.mu.Unlock()
	dnsttCmd, err := StartDnstt(ctx, t.config, fwdPort)
	t.mu.Lock()

	if err != nil {
		Tracef("[ssh-slowdns] ERROR dnstt phase: %v", err)
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.slowdnscmd = dnsttCmd
	Tracef("[ssh-slowdns] phase 2/2: ssh dial through 127.0.0.1:%d", fwdPort)
	sshClient, dialErr := sshDial(t.config, fmt.Sprintf("127.0.0.1:%d", fwdPort))
	if dialErr != nil {
		Tracef("[ssh-slowdns] ERROR ssh dial: %v", dialErr)
		t.slowdnscmd.Process.Kill()
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(dialErr.Error())
		return fmt.Errorf("ssh dial through SlowDNS failed: %w", dialErr)
	}

	socksAddr, _, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Tracef("[ssh-slowdns] ERROR socks port: %v", err)
		sshClient.Close()
		t.slowdnscmd.Process.Kill()
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		Tracef("[ssh-slowdns] ERROR socks listen %s: %v", socksAddr, err)
		ClearLiveSocksAddr(t.config.ID)
		sshClient.Close()
		t.slowdnscmd.Process.Kill()
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("socks listen failed: %w", err)
	}
	Tracef("[ssh-slowdns] SOCKS listening on %s", socksAddr)

	t.ctx = ctx
	t.client = sshClient
	t.ln = ln
	serveSocks5(t.ctx, ln, sshClient)

	t.startTime = time.Now()
	t.status = StatusRunning
	Tracef("[ssh-slowdns] RUNNING name=%q", t.config.Name)
	go t.monitor()
	return nil
}

func (t *NativeSSHSlowDNSTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.status == StatusStopped {
		return nil
	}
	Tracef("[ssh-slowdns] Stop() name=%q", t.config.Name)
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
		Tracef("[ssh-slowdns] slowdns reaped")
	}
	ClearLiveForward(t.config.ID)
	ClearLiveSocksAddr(t.config.ID)
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
	Tracef("[ssh-slowdns] connection closed (monitor)")
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
