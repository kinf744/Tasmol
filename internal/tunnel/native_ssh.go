package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"vpn-app/internal/config"
)

// This file implements SSH without the external openssh binary, for
// platforms where it cannot be executed (Android APK). It uses
// golang.org/x/crypto/ssh plus a minimal embedded SOCKS5 CONNECT server.
// Host-key checking mirrors the process implementation
// (StrictHostKeyChecking=no).

// sshTLSRequested reports whether this profile wraps the SSH handshake in
// TLS ("SSH-TLS*" modes). The flag is set by the editor (Advanced["ssh_tls"])
// and the SNI/version in Server.SNI / Advanced["ssh_tls_version"].
func sshTLSRequested(cfg *config.TunnelConfig) bool {
	if advBool(cfg.Advanced, "ssh_tls", false) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(cfg.Transport.Security), "tls")
}

// tlsVersionRange maps the editor's TLS Version dropdown
// (default / 1.2 / 1.3) to a crypto/tls version window.
func tlsVersionRange(cfg *config.TunnelConfig) (minV, maxV uint16) {
	switch strings.TrimSpace(advStr(cfg.Advanced, "ssh_tls_version", "default")) {
	case "1.2", "tls1.2":
		return tls.VersionTLS12, tls.VersionTLS12
	case "1.3", "tls1.3":
		return tls.VersionTLS13, tls.VersionTLS13
	}
	return 0, 0 // Go defaults
}

// wrapSSHConn applies the TLS layer requested by the profile on top of the
// already-dialed raw TCP connection (direct or via the proxy hop). Returns
// the connection unchanged when TLS is not requested. The returned conn is a
// *bufferedConn when the handshake consumed bytes (see tls.Client over a
// conn read through a bufio.Reader is handled by the tls package itself).
func wrapSSHConn(cfg *config.TunnelConfig, conn net.Conn, addr string) (net.Conn, error) {
	if !sshTLSRequested(cfg) {
		return conn, nil
	}
	sni := strings.TrimSpace(cfg.Server.SNI)
	if sni == "" {
		sni, _, _ = splitProxyAddr(addr) // fall back to the target host
	}
	minV, maxV := tlsVersionRange(cfg)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // tunnel endpoints use self-signed certs
		MinVersion:         minV,
		MaxVersion:         maxV,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		Errorf("ssh", "TLS handshake (SNI=%s): %v", sni, err)
		return nil, fmt.Errorf("ssh TLS handshake: %w", err)
	}
	st := tlsConn.ConnectionState()
	Infof("ssh", "TLS established sni=%s version=0x%x cipher=0x%x alpn=%q",
		sni, st.Version, st.CipherSuite, st.NegotiatedProtocol)
	Tracef("[ssh] TLS wrap OK sni=%s", sni)
	return tlsConn, nil
}

// sshDial opens an SSH client connection from a tunnel config. When
// cfg.SSH.Proxy ("ip:port") is set, SSH is reached through an HTTP CONNECT
// hop carrying cfg.SSH.Payload (see dialViaProxy).
func sshDial(cfg *config.TunnelConfig, addr string) (*ssh.Client, error) {
	hasPass := cfg.Auth.Password != ""
	hasKey := strings.TrimSpace(cfg.Auth.PrivateKey) != ""
	hasPhrase := cfg.Auth.Passphrase != ""
	user := cfg.Auth.Username
	if advBool(cfg.Advanced, "hide_upass", false) {
		user = "••••"
	}
	Tracef("[ssh] dial begin addr=%s user=%q passwordSet=%v keySet=%v passphraseSet=%v proxy=%q payloadLen=%d",
		addr, user, hasPass, hasKey, hasPhrase,
		cfg.SSH.Proxy, len(cfg.SSH.Payload))
	// kighmu.txt : un resume lisible du protocole et de la chaine d'appels,
	// suivi de chaque etape (DNS -> TCP -> proxy -> TLS -> handshake).
	sshStep("dial start protocol=%s target=%s user=%s", sshModeName(cfg), addr, user)
	sshResolveEndpoint(cfg.Server.Host)
	if sshTLSRequested(cfg) {
		sshStep("tls requested sni=%q version=%s",
			strings.TrimSpace(cfg.Server.SNI), advStr(cfg.Advanced, "ssh_tls_version", "default"))
	}
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
			sshStep("private key parsed (passphrase=%v)", hasPhrase)
		} else {
			Errorf("ssh", "private key unparsable: %v", err)
			Infof("ssh", "  hint: cle PEM complete requise (BEGIN/END OPENSSH PRIVATE KEY)")
		}
	}
	if len(auth) == 0 {
		sshDiagError("auth", fmt.Errorf("no auth method (need auth.password or auth.private_key)"),
			"renseignez le mot de passe ou collez une cle privee dans Authentication")
		return nil, fmt.Errorf("ssh: no auth method (need auth.password or auth.private_key)")
	}
	sshStep("auth methods: password=%v private_key=%v", hasPass, hasKey)

	sshCfg := &ssh.ClientConfig{
		User:            cfg.Auth.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
		// Pre-auth server banner (MOTD header): surfaced in the journal
		// like the reference app's SSH_BANNER card. Skipped for locked
		// "Remove Banner" profiles.
		BannerCallback: func(message string) error {
			if advBool(cfg.Advanced, "remove_banner", false) {
				return nil
			}
			if m := cleanServerText(message, 300); m != "" {
				Journalf("ssh-banner", "%s", m)
			}
			return nil
		},
	}

	var client *ssh.Client
	if strings.TrimSpace(cfg.SSH.Proxy) != "" {
		Journalf("ssh", "hop via HTTP proxy %s", cfg.SSH.Proxy)
		sshStep("step 1/3 proxy CONNECT via %s", cfg.SSH.Proxy)
		conn, err := dialViaProxy(cfg.SSH.Proxy, addr, cfg.SSH.Payload, proxyAuthHeader(cfg))
		if err != nil {
			sshDiagError("proxy CONNECT", err,
				"le proxy doit repondre 200/101 ; verifiez ip:port, identifiants et payload")
			return nil, fmt.Errorf("ssh proxy hop: %w", err)
		}
		sshStep("proxy CONNECT established, wrapping transport")
		if conn, err = wrapSSHConn(cfg, conn, addr); err != nil {
			sshDiagError("tls wrap", err, "mode SSH-TLS : la cible doit parler TLS sur ce port")
			return nil, err
		}
		sshStep("step 2/3 ssh handshake over proxy")
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
		if err != nil {
			sshDiagError("ssh handshake via proxy", err, sshDialHints(cfg, err))
			conn.Close()
			return nil, err
		}
		Tracef("[ssh] handshake OK via proxy")
		sshStep("step 3/3 ssh session established (via proxy)")
		client = ssh.NewClient(c, chans, reqs)
	} else {
		Tracef("[ssh] direct dial %s ...", addr)
		sshStep("step 1/3 tcp connect %s", addr)
		rawConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
		if err != nil {
			sshDiagError("tcp connect", err,
				"port incorrect, serveur arrete, ou port bloque par l'operateur")
			return nil, fmt.Errorf("ssh dial: %w", err)
		}
		sshStep("tcp connected (%s -> %s)", rawConn.LocalAddr(), rawConn.RemoteAddr())
		conn, err := wrapSSHConn(cfg, rawConn, addr)
		if err != nil {
			sshDiagError("tls wrap", err, "mode SSH-TLS : la cible doit parler TLS sur ce port")
			return nil, err
		}
		sshStep("step 2/3 ssh handshake")
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
		if err != nil {
			sshDiagError("ssh handshake", err, sshDialHints(cfg, err))
			conn.Close()
			return nil, err
		}
		Tracef("[ssh] handshake OK")
		sshStep("step 3/3 ssh session established")
		client = ssh.NewClient(c, chans, reqs)
	}
	if v := strings.TrimSpace(string(client.ServerVersion())); v != "" {
		if !advBool(cfg.Advanced, "remove_banner", false) {
			Journalf("ssh-banner", "server version: %s", v)
		}
	}
	// Post-auth server message (MOTD): best-effort shell read, silent on
	// restricted shells. Mirrors the reference SSH_SERVER_MESSAGE card.
	// Skipped for locked "Remove Banner" profiles.
	if !advBool(cfg.Advanced, "remove_banner", false) {
		logServerMessage(client)
	}
	return client, nil
}

// ansiRe strips ANSI terminal escapes from server text.
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// cleanServerText makes server-sent text journal-safe: no ANSI, no control
// bytes, trimmed, capped.
func cleanServerText(s string, max int) string {
	s = ansiRe.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 32 && r != 127) {
			b.WriteRune(r)
		}
	}
	s = strings.TrimSpace(b.String())
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// logServerMessage captures up to a few MOTD lines through a throwaway shell
// session (3s budget). Any failure is silent: some servers forbid shells.
// The session is always closed (even on timeout) so server-side session
// slots never leak across reconnects.
func logServerMessage(client *ssh.Client) {
	var sessPtr atomic.Pointer[ssh.Session]
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess, err := client.NewSession()
		if err != nil {
			return
		}
		sessPtr.Store(sess)
		defer sess.Close()
		stdout, err := sess.StdoutPipe()
		if err != nil {
			return
		}
		if err := sess.Shell(); err != nil {
			return
		}
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 512)
		for len(buf) < 4096 {
			n, err := stdout.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if promptSeen(buf) {
					break
				}
			}
			if err != nil {
				break
			}
		}
		lines := 0
		for _, ln := range strings.Split(string(buf), "\n") {
			if lines >= 8 {
				break
			}
			if m := cleanServerText(ln, 200); m != "" && !isShellPrompt(m) {
				Journalf("ssh-message", "%s", m)
				lines++
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		if sess := sessPtr.Load(); sess != nil {
			_ = sess.Close()
		}
		<-done
	}
}

// promptSeen stops the MOTD read once a shell prompt line appears.
func promptSeen(buf []byte) bool {
	s := string(buf)
	i := strings.LastIndexByte(s, '\n')
	if i < 0 {
		i = 0
	} else {
		i++
	}
	last := strings.TrimRight(s[i:], " \t\r\n")
	return strings.HasSuffix(last, "$") || strings.HasSuffix(last, "#") || strings.HasSuffix(last, ">")
}

// isShellPrompt drops prompt echo lines (user@host, trailing $/#) from the
// journal; the message body is what matters.
func isShellPrompt(line string) bool {
	t := strings.TrimSpace(line)
	if strings.Contains(t, "@") {
		return true
	}
	return strings.HasSuffix(t, "$") || strings.HasSuffix(t, "#")
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
	p = strings.ReplaceAll(p, "[real_host]", host)
	p = strings.ReplaceAll(p, "[REAL_HOST]", host)
	// Pasted HTTP-Custom payloads carry literal backslash escapes.
	p = strings.ReplaceAll(p, "\\r\\n", "\r\n")
	p = strings.ReplaceAll(p, "\\r", "\r")
	p = strings.ReplaceAll(p, "\\n", "\n")
	// [split]/[delay] DPI-evasion markers are kept for sendPayload, which
	// transmits the chunks with inter-part sleeps (never sent literally).
	return p
}

// sendPayload writes the payload, honoring Injector DPI-evasion markers:
// [split] parts go out 30ms apart, [delay] lines 20ms apart; otherwise one
// shot. Markers themselves are never transmitted.
func sendPayload(conn net.Conn, payload, raw string) error {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "[split]") {
		parts := splitMarker(payload, "[split]")
		for i, part := range parts {
			if _, err := io.WriteString(conn, part); err != nil {
				return err
			}
			if i < len(parts)-1 {
				time.Sleep(30 * time.Millisecond)
			}
		}
		return nil
	}
	if strings.Contains(lower, "[delay]") {
		lines := strings.Split(payload, "\r\n")
		for i, line := range lines {
			data := line
			if i < len(lines)-1 {
				data += "\r\n"
			}
			if _, err := io.WriteString(conn, data); err != nil {
				return err
			}
			if i < len(lines)-1 {
				time.Sleep(20 * time.Millisecond)
			}
		}
		return nil
	}
	_, err := io.WriteString(conn, payload)
	return err
}

// splitMarker splits s on marker case-insensitively, dropping the markers.
func splitMarker(s, marker string) []string {
	var out []string
	lower := strings.ToLower(s)
	lm := strings.ToLower(marker)
	for {
		i := strings.Index(lower, lm)
		if i < 0 {
			out = append(out, s)
			return out
		}
		out = append(out, s[:i])
		s = s[i+len(marker):]
		lower = lower[i+len(marker):]
	}
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

// proxyAuthHeader builds the Proxy-Authorization value when the editor set
// proxy credentials ("Authenticate Proxy"), empty otherwise.
func proxyAuthHeader(cfg *config.TunnelConfig) string {
	user := strings.TrimSpace(advStr(cfg.Advanced, "proxy_user", ""))
	pass := advStr(cfg.Advanced, "proxy_pass", "")
	if user == "" {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// dialViaProxy opens a TCP connection to an HTTP proxy and issues a CONNECT
// request (with the optional custom payload) towards addr. authHeader is an
// optional Proxy-Authorization value.
func dialViaProxy(proxyAddr, addr, payloadTpl, authHeader string) (net.Conn, error) {
	Tracef("[ssh] proxy hop: proxy=%s target=%s payloadLen=%d", proxyAddr, addr, len(payloadTpl))
	proxyHost, proxyPort, err := splitProxyAddr(proxyAddr)
	if err != nil {
		Errorf("ssh", "bad proxy addr: %v", err)
		return nil, err
	}
	host, port, err := splitProxyAddr(addr)
	if err != nil {
		Errorf("ssh", "bad target addr: %v", err)
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
		Errorf("ssh", "dial proxy %s:%s: %v (proxy unreachable: wrong IP/port, proxy down, or carrier-filtered)", proxyHost, proxyPort, err)
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}

	var req strings.Builder
	// isConnect mirrors the reference engine: only a CONNECT request
	// demands 200/101; other methods (or the auto default) fail solely on
	// explicit proxy errors.
	isConnect := strings.TrimSpace(payloadTpl) == ""
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
			isConnect = strings.HasPrefix(strings.ToUpper(strings.TrimLeft(body, " \t\r\n")), "CONNECT ")
		} else {
			req.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
			req.WriteString("Host: " + addr + "\r\n")
			if body != "" {
				if !strings.HasSuffix(body, "\r\n") {
					body += "\r\n"
				}
				req.WriteString(body)
			}
			isConnect = true
		}
	} else {
		req.WriteString("CONNECT " + addr + " HTTP/1.1\r\n")
		req.WriteString("Host: " + addr + "\r\n")
		req.WriteString("Proxy-Connection: Keep-Alive\r\n")
	}
	if authHeader != "" && !strings.Contains(strings.ToLower(req.String()), "proxy-authorization") {
		req.WriteString("Proxy-Authorization: " + authHeader + "\r\n")
	}
	req.WriteString("\r\n")

	if lines := strings.Split(req.String(), "\r\n"); len(lines) > 0 {
		Tracef("[ssh] CONNECT request line: %s (+%d header/payload lines)", lines[0], len(lines)-1)
	}
	if err := sendPayload(conn, req.String(), payloadTpl); err != nil {
		Errorf("ssh", "proxy write: %v", err)
		conn.Close()
		return nil, fmt.Errorf("proxy write: %w", err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		Errorf("ssh", "proxy read: %v", err)
		conn.Close()
		return nil, fmt.Errorf("proxy read: %w", err)
	}
	Journalf("ssh", "proxy status: %s", strings.TrimSpace(status))
	code := proxyStatusCode(status)
	// Reference-engine rule: hard proxy errors always fail; a CONNECT
	// additionally demands 200, or 101 (WS-panel "tunnel open" convention).
	if code == 400 || code == 403 || code == 404 || code == 407 || code == 500 || code == 502 {
		conn.Close()
		return nil, fmt.Errorf("proxy error: %s", strings.TrimSpace(status))
	}
	if isConnect && code != 200 && code != 101 {
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

// hideUser masks the username for locked "Hide UPass" profiles.
func hideUser(cfg *config.TunnelConfig, user string) string {
	if advBool(cfg.Advanced, "hide_upass", false) {
		return "••••"
	}
	return user
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

	target := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	remote, err := sshClient.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		// Destination injoignable depuis le VPS : tres frequent sur un
		// serveur qui ne filtre que DNS ou un port precis.
		Connf("ssh", "SOCKS5 -> %s refuse (%v) apres %s",
			target, err, time.Since(start).Round(time.Millisecond))
		return
	}
	defer remote.Close()

	// Success reply (bound address zeroed).
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	Tracef("[ssh] SOCKS5 relay %s open", target)

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
	logSSHProfile(t.config, "native (in-process SSH)", 0)
	Tracef("[ssh] ssh %q@%s:%d via proxy %q",
		hideUser(t.config, t.config.Auth.Username), t.config.Server.Host, t.config.Server.Port, t.config.SSH.Proxy)
	if t.config.Server.Host == "" || t.config.Auth.Username == "" {
		Errorf("ssh", "host or username empty")
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
		Errorf("ssh", "sshDial: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("ssh dial failed: %w", err)
	}

	// Fresh random SOCKS port per session (override respected): never
	// reuse, never collide with a draining previous session.
	ClearLiveSocksAddr(t.config.ID)
	socksAddr, _, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Errorf("ssh", "socks port: %v", err)
		client.Close()
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	Tracef("[ssh] SOCKS picked %s", socksAddr)
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		Errorf("ssh", "socks listen %s: %v", socksAddr, err)
		ClearLiveSocksAddr(t.config.ID)
		client.Close()
		t.status = StatusError
		t.setError(err.Error())
		return fmt.Errorf("socks listen failed: %w", err)
	}
	Tracef("[ssh] SOCKS listening on %s", socksAddr)
	Connf("ssh", "SOCKS5 ready on %s (protocol %s)", socksAddr, sshModeName(t.config))

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.client = client
	t.ln = ln
	// serveSocks5 blocks in Accept: always run it as a goroutine or
	// Start() never returns (session stuck in CONNECTING forever).
	go serveSocks5(t.ctx, ln, client)

	t.startTime = time.Now()
	t.status = StatusRunning
	Tracef("[ssh] RUNNING name=%q", t.config.Name)
	Connf("ssh", "tunnel %q RUNNING", t.config.Name)
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
	logSSHStop(t.config, nil)
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
		// Cause lisible dans kighmu.txt : le tunnel ne s'est pas arrete
		// sur demande, la session SSH a coupe d'elle-meme.
		Warnf("ssh", "session SSH perdue (connexion fermee par le serveur ou le reseau) pour %q ;"+
			" les kept-alives ne sont pas configures, l'app tente un reconnexion via auto-follow",
			t.config.Name)
	} else {
		logSSHStop(t.config, nil)
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
	Journalf("ssh-slowdns", "slowdns ns=%q user=%q key=%d chars",
		t.nsDomain(), t.config.Auth.Username, len(strings.TrimSpace(t.config.Server.PublicKey)))
	logSSHProfile(t.config, "native SSH + dnstt (DNS tunnel)", 0)
	if t.nsDomain() == "" {
		sshDiagError("dnstt nameserver", fmt.Errorf("nameserver domain empty"),
			"renseignez le NS du serveur dnstt (ex. ns4.exemple.com)")
		return fmt.Errorf("slowdns nameserver domain is required (server.nameserver)")
	}
	if DnsttPubKey(t.config) == "" {
		sshDiagError("dnstt public key", fmt.Errorf("public key empty"),
			"cle publique du serveur dnstt requise (server.public_key)")
		return fmt.Errorf("slowdns server public key is required (server.public_key or advanced.slowdns_pubkey)")
	}
	if t.config.Auth.Username == "" {
		sshDiagError("ssh username", fmt.Errorf("username empty"), "renseignez l'utilisateur SSH")
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
		Errorf("ssh-slowdns", "fwd port: %v", err)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}

	// dnstt first (shared helper with output capture).
	Tracef("[ssh-slowdns] phase 1/2: dnstt forward :%d", fwdPort)
	Connf("ssh", "SlowDNS phase 1/2 : demarrage dnstt -> 127.0.0.1:%d (ns=%s resolver=%s)",
		fwdPort, DnsttDomain(t.config), DnsttResolver(t.config))
	t.mu.Unlock()
	dnsttCmd, err := StartDnstt(ctx, t.config, fwdPort)
	t.mu.Lock()

	if err != nil {
		sshDiagError("dnstt", err,
			"verifiez NS, cle publique, resolver et que le serveur dnstt repond")
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	t.slowdnscmd = dnsttCmd
	Tracef("[ssh-slowdns] phase 2/2: ssh dial through 127.0.0.1:%d", fwdPort)
	Connf("ssh", "SlowDNS phase 2/2 : handshake SSH via le forward DNS")
	sshClient, dialErr := sshDial(t.config, fmt.Sprintf("127.0.0.1:%d", fwdPort))
	if dialErr != nil {
		sshDiagError("ssh over SlowDNS", dialErr, sshDialHints(t.config, dialErr))
		t.slowdnscmd.Process.Kill()
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(dialErr.Error())
		return fmt.Errorf("ssh dial through SlowDNS failed: %w", dialErr)
	}

	socksAddr, _, err := PickLiveSocksAddr(t.config)
	if err != nil {
		Errorf("ssh-slowdns", "socks port: %v", err)
		sshClient.Close()
		t.slowdnscmd.Process.Kill()
		ClearLiveForward(t.config.ID)
		t.status = StatusError
		t.setError(err.Error())
		return err
	}
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		Errorf("ssh-slowdns", "socks listen %s: %v", socksAddr, err)
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
	// serveSocks5 blocks in Accept: always run it as a goroutine or
	// Start() never returns (session stuck in CONNECTING forever).
	go serveSocks5(t.ctx, ln, sshClient)

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
		// Un tunnel DNS qui meurt laisse souvent le profil bloque en
		// CONNECTING : dire quel processus est mort evite de chercher
		// a l'aveugle.
		if t.slowdnscmd != nil && t.slowdnscmd.ProcessState != nil {
			sshDiagError("dnstt", fmt.Errorf("process exited (%s)", t.slowdnscmd.ProcessState),
				"le forward DNS a coupe")
		} else {
			Warnf("ssh", "session SSH/DNS fermee pour %q (coupe reseau ou serveur)",
				t.config.Name)
		}
	} else {
		logSSHStop(t.config, nil)
	}
}

func (t *NativeSSHSlowDNSTunnel) setError(msg string) {
	t.stats.LastError = msg
	t.stats.UpdatedAt = time.Now()
}
