package tunnel

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vpn-app/internal/config"
)

// Advanced map keys used by Xray tunnels.
const (
	// OutboundJSONKey holds a complete Xray outbound object (JSON string or
	// map) used verbatim, e.g. produced from vmess/vless/trojan/shadowsocks
	// links or pasted by the user. It takes precedence over the structured
	// fields and unlocks protocols/transports beyond manual VLESS.
	OutboundJSONKey = "outbound_json"
	// LinkKey keeps the original subscription link for reference.
	LinkKey = "link"
)

// Supported transports for Xray/Xray-SlowDNS tunnels (manual fields,
// links and raw JSON outbounds).
var supportedTransports = []string{"tcp", "ws", "grpc", "xhttp", "httpupgrade"}

// SupportedTransports returns the transport list for UI dropdowns.
func SupportedTransports() []string {
	out := make([]string, len(supportedTransports))
	copy(out, supportedTransports)
	return out
}

// buildStreamSettings builds Xray streamSettings for every supported
// transport (tcp/ws/grpc/xhttp/httpupgrade) and security (none/tls/reality).
// If dialAddr is an IP literal, allowInsecure is forced true because TLS
// certs are almost never valid for raw IPs (SAN = domain names).
func buildStreamSettings(cfg *config.TunnelConfig, dialAddr string) map[string]interface{} {
	ss := map[string]interface{}{
		"network":  cfg.Transport.Network,
		"security": cfg.Transport.Security,
	}

	switch cfg.Transport.Network {
	case "ws":
		ss["wsSettings"] = map[string]interface{}{
			"path": cfg.Transport.Path,
			"headers": map[string]string{
				"Host": cfg.Transport.Host,
			},
		}
	case "grpc":
		grpc := map[string]interface{}{
			"serviceName": cfg.Transport.Path,
			"multiMode":   false,
		}
		if cfg.Transport.Host != "" {
			grpc["authority"] = cfg.Transport.Host
		}
		ss["grpcSettings"] = grpc
	case "xhttp":
		xhttp := map[string]interface{}{
			"path": cfg.Transport.Path,
		}
		if cfg.Transport.Host != "" {
			xhttp["host"] = cfg.Transport.Host
		}
		ss["xhttpSettings"] = xhttp
	case "httpupgrade":
		hu := map[string]interface{}{
			"path": cfg.Transport.Path,
		}
		if cfg.Transport.Host != "" {
			hu["host"] = cfg.Transport.Host
		}
		ss["httpupgradeSettings"] = hu
	case "tcp":
		ss["tcpSettings"] = map[string]interface{}{
			"header": map[string]interface{}{"type": "none"},
		}
	}

	if cfg.Transport.Security == "tls" {
		// NOTE: never emit "allowInsecure": Xray 26.x removed it and
		// aborts startup when present. IP-literal endpoints are handled
		// by resolveDialAddr (SNI domain) + probeCertPins (cert pinning).
		ss["tlsSettings"] = map[string]interface{}{
			"serverName":  cfg.Server.SNI,
			"fingerprint": cfg.Transport.Fingerprint,
			"alpn":        cfg.Transport.ALPN,
		}
	}

	if cfg.Transport.Security == "reality" {
		ss["realitySettings"] = map[string]interface{}{
			"serverName":  cfg.Server.SNI,
			"publicKey":   cfg.Server.PublicKey,
			"shortId":     cfg.Server.ShortID,
			"fingerprint": cfg.Transport.Fingerprint,
		}
	}

	return ss
}

// isIPLiteral reports whether addr parses as an IP (v4/v6).
func isIPLiteral(addr string) bool {
	return net.ParseIP(strings.TrimSpace(addr)) != nil
}

// isLoopback reports loopback addresses (local dnstt forwards need no
// TLS tricks: the real endpoint sits behind the forward).
func isLoopback(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	return ip != nil && ip.IsLoopback()
}

// resolveDialAddr is intentionally identity: Xray must never receive a
// domain to dial — its child-process resolver is dead on Android
// ([::1]:53 refused) and domainStrategy does not cover transport dials.
// Domains are resolved up-front by resolveEndpoint; TLS trust survives via
// SNI serverName + live chain pinning (patchStoredTLS).
func resolveDialAddr(cfg *config.TunnelConfig, addr string) string {
	return addr
}

// resolveEndpoint turns a domain endpoint into a dialable IP using the app
// process resolver (which works: Bionic/netd), because the xray child can
// resolve nothing. IP literals and loopback forwards pass through
// untouched. TLS keeps working via serverName SNI + live chain pinning.
func resolveEndpoint(cfg *config.TunnelConfig, addr string) string {
	if cfg == nil || isIPLiteral(addr) || isLoopback(addr) {
		return addr
	}
	name := strings.TrimSpace(addr)
	if ip, err := net.ResolveIPAddr("ip4", name); err == nil && ip != nil {
		Tracef("[xray] endpoint %s resolves to %s: dialing the IP (child DNS is dead)", name, ip.String())
		return ip.String()
	}
	if ip, err := net.ResolveIPAddr("ip", name); err == nil && ip != nil {
		Tracef("[xray] endpoint %s resolves to %s: dialing the IP (child DNS is dead)", name, ip.String())
		return ip.String()
	} else {
		Warnf("xray", "endpoint %s unresolvable here, passing through: %v", name, err)
	}
	return addr
}

// probeCertPins opens one throwaway TLS handshake (no verification) and
// hashes the presented chain into base64-encoded SHA-256 digests that feed
// Xray 26.x "pinnedPeerCertSha256" (the supported replacement for the
// removed "allowInsecure"), so self-signed / IP-only certs connect. Xray
// matches ANY entry against the peer chain (leaf or CA).
func probeCertPins(addr string, port int, sni string) ([]string, error) {
	serverName := sni
	if serverName == "" || isIPLiteral(serverName) {
		serverName = addr
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	// The system resolver can be blocked (carrier DNS hijack, freebasics
	// networks): fall back to direct UDP DNS so the probe still succeeds.
	dialer.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			for _, dns := range []string{"8.8.8.8:53", "1.1.1.1:53"} {
				if c, err := d.DialContext(ctx, "udp", dns); err == nil {
					return c, nil
				}
			}
			return d.DialContext(ctx, network, address)
		},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp",
		net.JoinHostPort(addr, strconv.Itoa(port)), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return hashPeerChain(conn)
}

// probeCertPinsViaHTTPProxy is probeCertPins through an HTTP CONNECT proxy
// (proxySettings.tag chains, e.g. freebasics carriers where every direct
// connection — including the probe's DNS lookup — is blocked). The proxy
// resolves the target name itself, so no local DNS is required, and the
// probed chain is exactly the one the real traffic will see.
func probeCertPinsViaHTTPProxy(proxyAddr string, proxyPort int, target string, sni string) ([]string, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(proxyAddr, strconv.Itoa(proxyPort)))
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	authority := target
	if _, _, err := net.SplitHostPort(target); err != nil {
		authority = net.JoinHostPort(target, "443")
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("proxy CONNECT read: %w", err)
	}
	if !strings.Contains(status, " 200") {
		return nil, fmt.Errorf("proxy CONNECT rejected: %s", strings.TrimSpace(status))
	}
	// Drain remaining CONNECT response headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("proxy CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	serverName := sni
	if serverName == "" {
		if host, _, err := net.SplitHostPort(authority); err == nil {
			serverName = host
		} else {
			serverName = authority
		}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS through proxy: %w", err)
	}
	return hashPeerChain(tlsConn)
}

func hashPeerChain(conn *tls.Conn) ([]string, error) {
	var pins []string
	seen := map[string]bool{}
	for _, cert := range conn.ConnectionState().PeerCertificates {
		sum := sha256.Sum256(cert.Raw)
		h := base64.StdEncoding.EncodeToString(sum[:])
		if !seen[h] {
			seen[h] = true
			pins = append(pins, h)
		}
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	return pins, nil
}

// httpProxyDialTarget extracts the CONNECT proxy address/port from an
// outbound: protocol "http" with settings.servers[0]. Returns ok=false for
// any other shape.
func httpProxyDialTarget(ob map[string]interface{}) (string, int, bool) {
	proto, _ := ob["protocol"].(string)
	if proto != "http" {
		return "", 0, false
	}
	addr, port := outboundDialTarget(ob)
	if addr == "" || port <= 0 {
		return "", 0, false
	}
	return addr, port, true
}

// patchStoredTLS migrates a stored (link-imported or pasted) outbound to
// what the bundled Xray accepts and the network requires:
//   - drops "allowInsecure" (removed in Xray 26.x: it aborts startup);
//   - pins the live peer cert chain when the endpoint stays a raw IP, so
//     self-signed / IP-only certs connect without disabling verification.
func patchStoredTLS(ob map[string]interface{}, cfg *config.TunnelConfig, addr string, port int) {
	ss, ok := ob["streamSettings"].(map[string]interface{})
	if !ok {
		return
	}
	sec, _ := ss["security"].(string)
	if sec == "" && cfg != nil {
		sec = cfg.Transport.Security
	}
	if sec != "tls" {
		return
	}
	tlsm, ok := ss["tlsSettings"].(map[string]interface{})
	if !ok {
		return
	}
	if _, bad := tlsm["allowInsecure"]; bad {
		delete(tlsm, "allowInsecure")
		Tracef("[xray] dropped removed allowInsecure (Xray 26.x)")
	}
	if isIPLiteral(addr) && !isLoopback(addr) {
		sni := ""
		if cfg != nil {
			sni = strings.TrimSpace(cfg.Server.SNI)
		}
		pins, err := probeCertPins(addr, port, sni)
		if err != nil {
			Tracef("[xray] cert probe %s:%d failed: %v (strict verification)", addr, port, err)
			return
		}
		// Xray matches a handshake when ANY pinned hash matches a chain
		// cert (leaf or any CA in the chain). Pin the whole chain so
		// intermediates/leaf rotations still pass verification.
		tlsm["pinnedPeerCertSha256"] = pins
		Tracef("[xray] pinned cert chain for %s:%d (%d in chain)", addr, port, len(pins))
	}
}

// BuildVmessOutbound builds a VMess outbound object.
func BuildVmessOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	security := cfg.Auth.Method
	if security == "" {
		security = "auto"
	}
	addr = resolveDialAddr(cfg, addr)
	return map[string]interface{}{
		"protocol": "vmess",
		"tag":      "proxy",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": addr,
					"port":    port,
					"users": []map[string]interface{}{
						{"id": cfg.Auth.UUID, "alterId": 0, "security": security},
					},
				},
			},
		},
		"streamSettings": buildStreamSettings(cfg, addr),
	}
}

// BuildTrojanOutbound builds a Trojan outbound object.
func BuildTrojanOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	addr = resolveDialAddr(cfg, addr)
	return map[string]interface{}{
		"protocol": "trojan",
		"tag":      "proxy",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": addr, "port": port, "password": cfg.Auth.Password},
			},
		},
		"streamSettings": buildStreamSettings(cfg, addr),
	}
}

// BuildShadowsocksOutbound builds a Shadowsocks outbound object.
func BuildShadowsocksOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	method := cfg.Auth.Method
	if method == "" {
		method = "aes-256-gcm"
	}
	addr = resolveDialAddr(cfg, addr)
	return map[string]interface{}{
		"protocol": "shadowsocks",
		"tag":      "proxy",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address": addr, "port": port,
					"method": method, "password": cfg.Auth.Password,
				},
			},
		},
		"streamSettings": buildStreamSettings(cfg, addr),
	}
}

// HasOutboundJSON reports whether the config carries a verbatim outbound.
func HasOutboundJSON(cfg *config.TunnelConfig) bool {
	if cfg == nil || cfg.Advanced == nil {
		return false
	}
	raw, ok := cfg.Advanced[OutboundJSONKey]
	if !ok {
		return false
	}
	if s, ok := raw.(string); ok {
		return s != ""
	}
	return raw != nil
}

// FullXrayConfigJSON returns the stored outbound_json as a complete Xray
// client config (dns/inbounds/outbounds/policy/...) when it has an
// "outbounds" array — Picko-style full configs pasted by the user. The
// local SOCKS inbound is normalized to listen on 127.0.0.1:socksPort,
// removed-in-26.x "allowInsecure" keys are dropped, everything else is
// used verbatim (proxy chains, policy, dns...). Not a full config → false.
func FullXrayConfigJSON(cfg *config.TunnelConfig, socksPort int) (string, bool) {
	if cfg == nil || cfg.Advanced == nil {
		return "", false
	}
	raw, ok := cfg.Advanced[OutboundJSONKey]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return "", false
	}
	outs, ok := m["outbounds"].([]interface{})
	if !ok || len(outs) == 0 {
		return "", false
	}

	// Socks inbound: bind the app-dialed local port, exactly one.
	var inbounds []interface{}
	for _, v := range asList(m["inbounds"]) {
		if im, ok := v.(map[string]interface{}); ok && im["protocol"] == "socks" {
			continue // replaced below
		}
		inbounds = append(inbounds, v)
	}
	inbounds = append([]interface{}{map[string]interface{}{
		"listen":   "127.0.0.1",
		"port":     socksPort,
		"protocol": "socks",
		"settings": map[string]interface{}{"udp": true, "auth": "noauth"},
	}}, inbounds...)
	m["inbounds"] = inbounds

	// Xray 26.x aborts on the removed allowInsecure key. Also: the bundled
	// xray is a linux/arm build, and on Android it finds no system CA pool
	// (x509 android loader requires GOOS=android), so every TLS dial fails
	// with "certificate signed by unknown authority". Pin the live peer
	// certificate for each TLS outbound instead (probe happens pre-VPN from
	// this process, whose resolver works).
	// Index outbounds by tag so proxySettings.tag chains can be resolved:
	// the probe must follow the SAME path as the real traffic.
	byTag := map[string]map[string]interface{}{}
	for _, v := range outs {
		if ob, ok := v.(map[string]interface{}); ok {
			if tag, _ := ob["tag"].(string); tag != "" {
				byTag[tag] = ob
			}
		}
	}

	for _, v := range outs {
		ob, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		ss, ok := ob["streamSettings"].(map[string]interface{})
		if !ok {
			continue
		}
		tlsm, ok := ss["tlsSettings"].(map[string]interface{})
		if !ok {
			continue
		}
		delete(tlsm, "allowInsecure")
		if _, has := tlsm["pinnedPeerCertSha256"]; has {
			continue
		}
		addr, port := outboundDialTarget(ob)
		if addr == "" || port <= 0 || isLoopback(addr) {
			continue
		}
		sni, _ := tlsm["serverName"].(string)
		target := net.JoinHostPort(addr, strconv.Itoa(port))

		var pins []string
		var err error
		// Chained through an HTTP proxy (proxySettings.tag)? Probe through
		// it: on freebasics-style networks direct dialing and local DNS are
		// blocked, so a direct probe always fails even though the real path
		// works.
		if ps, ok := ob["proxySettings"].(map[string]interface{}); ok {
			if tag, _ := ps["tag"].(string); tag != "" {
				if hop, ok2 := byTag[tag]; ok2 {
					if pAddr, pPort, isHTTP := httpProxyDialTarget(hop); isHTTP {
						pins, err = probeCertPinsViaHTTPProxy(pAddr, pPort, target, sni)
						if err != nil {
							Warnf("xray", "full-config TLS probe %s via proxy %s:%d failed: %v (strict verification)", target, pAddr, pPort, err)
							continue
						}
						Tracef("[xray] full-config: pinned cert chain for %s via proxy %s:%d", target, pAddr, pPort)
					}
				}
			}
		}
		if pins == nil && err == nil {
			pins, err = probeCertPins(addr, port, sni)
			if err != nil {
				Warnf("xray", "full-config TLS probe %s:%d failed: %v (strict verification)", addr, port, err)
				continue
			}
			Tracef("[xray] full-config: pinned cert chain for %s:%d", addr, port)
		}
		tlsm["pinnedPeerCertSha256"] = pins
	}

	data, err := json.Marshal(m)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func asList(v interface{}) []interface{} {
	if l, ok := v.([]interface{}); ok {
		return l
	}
	return nil
}

// outboundDialTarget extracts address/port from an outbound's
// settings.vnext[0] (vless/vmess) or settings.servers[0] (trojan/ss/http).
func outboundDialTarget(ob map[string]interface{}) (string, int) {
	s, ok := ob["settings"].(map[string]interface{})
	if !ok {
		return "", 0
	}
	for _, key := range []string{"vnext", "servers"} {
		for _, v := range asList(s[key]) {
			if m, ok := v.(map[string]interface{}); ok {
				addr, _ := m["address"].(string)
				return addr, parsePortAny(m["port"])
			}
		}
	}
	return "", 0
}

// TunnelOutbound returns the outbound object for an Xray-family tunnel:
// Advanced["outbound_json"] verbatim when present (links, pasted JSON),
// otherwise the structured VLESS builder. Transport-layer chaining options
// (proxySettings.tag, TransportLayer) are layered onto the result regardless
// of its source, and any extra outbounds declared via Advanced["outbounds"]
// are included as siblings by the config generators.
func TunnelOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	// Domains are unresolvable by the xray child: dial a self-resolved IP.
	addr = resolveEndpoint(cfg, addr)
	var ob map[string]interface{}
	if cfg.Advanced != nil {
		if raw, ok := cfg.Advanced[OutboundJSONKey]; ok {
			var m map[string]interface{}
			switch v := raw.(type) {
			case string:
				if err := json.Unmarshal([]byte(v), &m); err == nil && m != nil {
					break
				}
			case map[string]interface{}:
				m = v
			}
			if m != nil {
				if tag, _ := m["tag"].(string); tag == "" {
					m["tag"] = "proxy"
				}
				// Honor the CURRENT host/port fields (they may have been
				// edited after the link import that produced this JSON),
				// preferring the SNI domain over a raw IP for TLS, then
				// migrate TLS settings for Xray 26.x (drop allowInsecure,
				// pin the live chain for bare IPs).
				addr = resolveDialAddr(cfg, addr)
				rewriteOutboundAddr(m, addr, port)
				patchStoredTLS(m, cfg, addr, port)
				ob = m
			}
		}
	}
	if ob == nil {
		ob = BuildVlessOutbound(cfg, addr, port)
	}
	applyOutboundChainOptions(ob, cfg)
	return ob
}

// SlowDNSOutbound is TunnelOutbound with the server address rewritten to
// the local dnstt forward. Required for xray_slowdns tunnels carrying a
// parsed link / pasted JSON (which embeds the real server address and
// would otherwise bypass the DNS tunnel).
func SlowDNSOutbound(cfg *config.TunnelConfig, fwdPort int) map[string]interface{} {
	ob := TunnelOutbound(cfg, "127.0.0.1", fwdPort)
	rewriteOutboundAddr(ob, "127.0.0.1", fwdPort)
	return ob
}

// rewriteOutboundAddr points vnext[] (vless/vmess) or servers[]
// (trojan/shadowsocks) at addr:port, tolerating both map shapes produced
// by the builders ([]map) and by JSON decoding ([]interface{}).
func rewriteOutboundAddr(ob map[string]interface{}, addr string, port int) {
	s, ok := ob["settings"].(map[string]interface{})
	if !ok {
		return
	}
	if rewriteAddrList(s["vnext"], addr, port) {
		return
	}
	rewriteAddrList(s["servers"], addr, port)
}

func rewriteAddrList(v interface{}, addr string, port int) bool {
	set := func(m map[string]interface{}) {
		m["address"] = addr
		m["port"] = port
	}
	switch arr := v.(type) {
	case []map[string]interface{}:
		if len(arr) == 0 {
			return false
		}
		set(arr[0])
		return true
	case []interface{}:
		if len(arr) == 0 {
			return false
		}
		if m, ok := arr[0].(map[string]interface{}); ok {
			set(m)
			return true
		}
	}
	return false
}

// proxySettingsTag returns the proxySettings.tag declared under
// Advanced["proxy_settings"], if any. The tag names a sibling outbound
// (e.g. a balancer lb-N member) that this outbound should chain through.
func proxySettingsTag(cfg *config.TunnelConfig) string {
	if cfg == nil || cfg.Advanced == nil {
		return ""
	}
	ps, ok := cfg.Advanced["proxy_settings"].(map[string]interface{})
	if !ok {
		return ""
	}
	tag, _ := ps["tag"].(string)
	return strings.TrimSpace(tag)
}

// applyOutboundChainOptions layers transport-layer chaining onto an outbound:
//   - Advanced["proxy_settings"].tag -> outbound.proxySettings.tag (only when
//     the outbound doesn't already carry its own proxySettings);
//   - Transport.TransportLayer -> streamSettings.sockopt.transportLayer = true.
//
// It guards the Xray-confirmed invariant that proxySettings.tag must NOT be
// combined with sockopt.dialerProxy (the binary aborts with
// "proxySettings.tag is conflicted with sockopt.dialerProxy"), so the
// transportLayer flag is only added when no dialerProxy is already present.
func applyOutboundChainOptions(ob map[string]interface{}, cfg *config.TunnelConfig) {
	if ob == nil || cfg == nil {
		return
	}
	if tag := proxySettingsTag(cfg); tag != "" {
		// proxySettings.tag conflicts with sockopt.dialerProxy (Xray aborts
		// with "proxySettings.tag is conflicted with sockopt.dialerProxy"),
		// so don't inject one when the outbound already dials via a proxy.
		if ob["proxySettings"] == nil && !hasDialerProxy(ob) {
			ob["proxySettings"] = map[string]interface{}{"tag": tag}
			Tracef("[xray] outbound %s chained via proxySettings.tag=%q", obTag(ob), tag)
		}
	}
	if !cfg.Transport.TransportLayer {
		return
	}
	ss, _ := ob["streamSettings"].(map[string]interface{})
	if ss == nil {
		return
	}
	sockopt, _ := ss["sockopt"].(map[string]interface{})
	if _, conflicted := sockopt["dialerProxy"]; conflicted {
		Warnf("xray", "TransportLayer skipped: sockopt.dialerProxy conflicts with proxySettings.tag")
		return
	}
	if sockopt == nil {
		sockopt = map[string]interface{}{}
		ss["sockopt"] = sockopt
	}
	if _, set := sockopt["transportLayer"]; !set {
		sockopt["transportLayer"] = true
		Tracef("[xray] outbound %s enabled streamSettings.sockopt.transportLayer", obTag(ob))
	}
}

func obTag(ob map[string]interface{}) string {
	if t, _ := ob["tag"].(string); t != "" {
		return t
	}
	return "<untagged>"
}

// hasDialerProxy reports whether the outbound already specifies a
// sockopt.dialerProxy (which conflicts with proxySettings.tag).
func hasDialerProxy(ob map[string]interface{}) bool {
	ss, ok := ob["streamSettings"].(map[string]interface{})
	if !ok {
		return false
	}
	sockopt, _ := ss["sockopt"].(map[string]interface{})
	_, exists := sockopt["dialerProxy"]
	return exists
}

// extraOutbounds returns sibling outbounds declared under
// Advanced["outbounds"] ([]interface{} or a JSON string). These are emitted
// alongside the main outbound so that a proxySettings.tag can resolve to an
// outbound defined on the same profile (e.g. a secondary proxy hop).
func extraOutbounds(cfg *config.TunnelConfig) []interface{} {
	if cfg == nil || cfg.Advanced == nil {
		return nil
	}
	raw, ok := cfg.Advanced["outbounds"]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		return v
	case string:
		var arr []interface{}
		if err := json.Unmarshal([]byte(v), &arr); err == nil {
			return arr
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Subscription link parsing (vmess / vless / trojan / shadowsocks).
// ParseXrayLink fills a TunnelConfig (display fields) and stores the
// normalized outbound JSON in Advanced["outbound_json"].
// ---------------------------------------------------------------------------

// ParseXrayLink parses a subscription link into a TunnelConfig.
func ParseXrayLink(link string) (config.TunnelConfig, error) {
	link = strings.TrimSpace(link)
	scheme := ""
	if i := strings.Index(link, "://"); i > 0 {
		scheme = strings.ToLower(link[:i])
	}
	switch scheme {
	case "vless":
		return parseVlessLink(link)
	case "vmess":
		return parseVmessLink(link)
	case "trojan":
		return parseTrojanLink(link)
	case "ss", "shadowsocks":
		return parseShadowsocksLink(link)
	default:
		return config.TunnelConfig{}, fmt.Errorf("unsupported link scheme %q (want vmess/vless/trojan/ss)", scheme)
	}
}

func linkName(u *url.URL, fallback string) string {
	if frag := u.EscapedFragment(); frag != "" {
		if name, err := url.PathUnescape(frag); err == nil && name != "" {
			return name
		}
	}
	if u.Fragment != "" {
		return u.Fragment
	}
	return fallback
}

func queryFirst(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func applyTransportFromQuery(cfg *config.TunnelConfig, q url.Values) {
	if t := queryFirst(q, "type"); t != "" {
		cfg.Transport.Network = strings.ToLower(t)
	}
	if p := queryFirst(q, "path"); p != "" {
		if un, err := url.PathUnescape(p); err == nil {
			p = un
		}
		cfg.Transport.Path = p
	}
	if h := queryFirst(q, "host", "authority"); h != "" {
		cfg.Transport.Host = h
	}
	if s := queryFirst(q, "serviceName", "service_name"); s != "" {
		cfg.Transport.Path = s
	}
	if sec := queryFirst(q, "security"); sec != "" {
		cfg.Transport.Security = strings.ToLower(sec)
	}
	if sni := queryFirst(q, "sni", "peer"); sni != "" {
		cfg.Server.SNI = sni
	}
	if fp := queryFirst(q, "fp", "fingerprint"); fp != "" {
		cfg.Transport.Fingerprint = fp
	}
	if alpn := queryFirst(q, "alpn"); alpn != "" {
		cfg.Transport.ALPN = strings.Split(alpn, ",")
	}
}

func storeOutbound(cfg *config.TunnelConfig, link string, outbound map[string]interface{}) (config.TunnelConfig, error) {
	raw, err := json.Marshal(outbound)
	if err != nil {
		return config.TunnelConfig{}, err
	}
	if cfg.Advanced == nil {
		cfg.Advanced = map[string]interface{}{}
	}
	cfg.Advanced[OutboundJSONKey] = string(raw)
	cfg.Advanced[LinkKey] = link
	return *cfg, nil
}

func parseVlessLink(link string) (config.TunnelConfig, error) {
	u, err := url.Parse(link)
	if err != nil {
		return config.TunnelConfig{}, fmt.Errorf("invalid vless link: %w", err)
	}
	var cfg config.TunnelConfig
	cfg.Type = config.TunnelXray
	cfg.Name = linkName(u, "vless")
	cfg.Auth.UUID = u.User.Username()
	cfg.Server.Host = u.Hostname()
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return config.TunnelConfig{}, fmt.Errorf("invalid vless port: %w", err)
		}
		cfg.Server.Port = port
	}
	q := u.Query()
	cfg.Auth.Flow = queryFirst(q, "flow")
	cfg.Transport.Network = "tcp"
	cfg.Transport.Security = "none"
	applyTransportFromQuery(&cfg, q)
	if cfg.Server.SNI == "" {
		cfg.Server.SNI = cfg.Server.Host
	}
	if pbk := queryFirst(q, "pbk", "publicKey"); pbk != "" {
		cfg.Server.PublicKey = pbk
	}
	if sid := queryFirst(q, "sid", "shortId", "short_id"); sid != "" {
		cfg.Server.ShortID = sid
	}
	outbound := BuildVlessOutbound(&cfg, cfg.Server.Host, cfg.Server.Port)
	return storeOutbound(&cfg, link, outbound)
}

func parseVmessLink(link string) (config.TunnelConfig, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	raw = strings.TrimSpace(raw)
	payload, err := decodeB64Flexible(raw)
	if err != nil {
		return config.TunnelConfig{}, fmt.Errorf("invalid vmess link: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return config.TunnelConfig{}, fmt.Errorf("invalid vmess json: %w", err)
	}
	str := func(key string) string {
		if v, ok := m[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	var cfg config.TunnelConfig
	cfg.Type = config.TunnelXray
	cfg.Name = str("ps")
	if cfg.Name == "" {
		cfg.Name = "vmess"
	}
	cfg.Server.Host = str("add")
	cfg.Server.Port = parsePortAny(m["port"])
	cfg.Auth.UUID = str("id")
	if scy := str("scy"); scy != "" {
		cfg.Auth.Method = scy
	}
	cfg.Transport.Network = strings.ToLower(str("net"))
	if cfg.Transport.Network == "" {
		cfg.Transport.Network = "tcp"
	}
	if tls := strings.ToLower(str("tls")); tls == "tls" {
		cfg.Transport.Security = "tls"
	}
	if h := str("host"); h != "" {
		cfg.Transport.Host = h
	}
	if p := str("path"); p != "" {
		cfg.Transport.Path = p
	}
	if sni := str("sni"); sni != "" {
		cfg.Server.SNI = sni
	} else {
		cfg.Server.SNI = cfg.Server.Host
	}
	if fp := str("fp"); fp != "" {
		cfg.Transport.Fingerprint = fp
	}
	if alpn := str("alpn"); alpn != "" {
		cfg.Transport.ALPN = strings.Split(alpn, ",")
	}
	outbound := BuildVmessOutbound(&cfg, cfg.Server.Host, cfg.Server.Port)
	return storeOutbound(&cfg, link, outbound)
}

func parseTrojanLink(link string) (config.TunnelConfig, error) {
	u, err := url.Parse(link)
	if err != nil {
		return config.TunnelConfig{}, fmt.Errorf("invalid trojan link: %w", err)
	}
	var cfg config.TunnelConfig
	cfg.Type = config.TunnelXray
	cfg.Name = linkName(u, "trojan")
	if pw := u.User.Username(); pw != "" {
		if un, err := url.PathUnescape(pw); err == nil {
			pw = un
		}
		cfg.Auth.Password = pw
	}
	cfg.Server.Host = u.Hostname()
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return config.TunnelConfig{}, fmt.Errorf("invalid trojan port: %w", err)
		}
		cfg.Server.Port = port
	} else {
		cfg.Server.Port = 443
	}
	q := u.Query()
	cfg.Transport.Network = "tcp"
	cfg.Transport.Security = "tls"
	applyTransportFromQuery(&cfg, q)
	if cfg.Server.SNI == "" {
		cfg.Server.SNI = cfg.Server.Host
	}
	if pbk := queryFirst(q, "pbk", "publicKey"); pbk != "" {
		cfg.Server.PublicKey = pbk
	}
	if sid := queryFirst(q, "sid", "shortId", "short_id"); sid != "" {
		cfg.Server.ShortID = sid
	}
	outbound := BuildTrojanOutbound(&cfg, cfg.Server.Host, cfg.Server.Port)
	return storeOutbound(&cfg, link, outbound)
}

func parseShadowsocksLink(link string) (config.TunnelConfig, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(link, "ss://"), "shadowsocks://"))

	// Strip fragment and query for address parsing.
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name = rest[i+1:]
		rest = rest[:i]
		if un, err := url.PathUnescape(name); err == nil {
			name = un
		}
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i] // plugins ignored
	}

	var method, password, host string
	var port int

	if i := strings.LastIndex(rest, "@"); i >= 0 {
		// ss://[base64(method:password) | method:password]@host:port
		userinfo := rest[:i]
		hostport := rest[i+1:]
		if !strings.Contains(userinfo, ":") {
			decoded, err := decodeB64Flexible(userinfo)
			if err != nil {
				return config.TunnelConfig{}, fmt.Errorf("invalid ss userinfo: %w", err)
			}
			userinfo = string(decoded)
		}
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 {
			return config.TunnelConfig{}, fmt.Errorf("invalid ss userinfo")
		}
		method, password = parts[0], parts[1]
		h, p, err := splitHostPort(hostport)
		if err != nil {
			return config.TunnelConfig{}, err
		}
		host, port = h, p
	} else {
		// ss://base64(method:password@host:port)
		decoded, err := decodeB64Flexible(rest)
		if err != nil {
			return config.TunnelConfig{}, fmt.Errorf("invalid ss link: %w", err)
		}
		inner := string(decoded)
		at := strings.LastIndex(inner, "@")
		if at < 0 {
			return config.TunnelConfig{}, fmt.Errorf("invalid ss link")
		}
		up := inner[:at]
		parts := strings.SplitN(up, ":", 2)
		if len(parts) != 2 {
			return config.TunnelConfig{}, fmt.Errorf("invalid ss userinfo")
		}
		method, password = parts[0], parts[1]
		h, p, err := splitHostPort(inner[at+1:])
		if err != nil {
			return config.TunnelConfig{}, err
		}
		host, port = h, p
	}

	var cfg config.TunnelConfig
	cfg.Type = config.TunnelXray
	cfg.Name = name
	if cfg.Name == "" {
		cfg.Name = "shadowsocks"
	}
	cfg.Server.Host = host
	cfg.Server.Port = port
	cfg.Auth.Method = method
	cfg.Auth.Password = password
	cfg.Transport.Network = "tcp"

	outbound := BuildShadowsocksOutbound(&cfg, host, port)
	return storeOutbound(&cfg, link, outbound)
}

// decodeB64Flexible decodes standard, URL-safe and unpadded base64.
func decodeB64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Tolerate missing padding explicitly.
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
		if b, err := base64.URLEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		return base64.StdEncoding.DecodeString(s)
	}
	return nil, fmt.Errorf("not base64")
}

func splitHostPort(hostport string) (string, int, error) {
	hostport = strings.TrimSpace(hostport)
	if strings.HasPrefix(hostport, "[") {
		h, p, err := splitBracketed(hostport)
		if err != nil {
			return "", 0, err
		}
		return h, p, nil
	}
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("missing port in %q", hostport)
	}
	port, err := strconv.Atoi(hostport[i+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", hostport)
	}
	return hostport[:i], port, nil
}

func splitBracketed(hostport string) (string, int, error) {
	end := strings.Index(hostport, "]")
	if end < 0 {
		return "", 0, fmt.Errorf("invalid ipv6 in %q", hostport)
	}
	host := hostport[1:end]
	rest := hostport[end+1:]
	if !strings.HasPrefix(rest, ":") {
		return "", 0, fmt.Errorf("missing port in %q", hostport)
	}
	port, err := strconv.Atoi(rest[1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", hostport)
	}
	return host, port, nil
}

func parsePortAny(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		if p, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return p
		}
	}
	return 0
}
