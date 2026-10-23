package tunnel

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vpn-app/internal/config"
)

const (
	OutboundJSONKey = "outbound_json"

	LinkKey = "link"
)

var supportedTransports = []string{"tcp", "ws", "grpc", "xhttp", "httpupgrade", "kcp", "http", "quic", "hysteria"}

func SupportedTransports() []string {
	out := make([]string, len(supportedTransports))
	copy(out, supportedTransports)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func allowInsecureTLS(cfg *config.TunnelConfig) bool {
	if cfg == nil || cfg.Advanced == nil {
		return true
	}
	raw, ok := cfg.Advanced["allow_insecure"]
	if !ok {
		return true
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		s := strings.TrimSpace(strings.ToLower(v))
		return !(s == "false" || s == "0" || s == "no")
	}
	return true
}

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
	case "kcp", "mkcp":

		kcp := map[string]interface{}{
			"mtu":              advInt(cfg.Advanced, "kcp_mtu", 1350),
			"tti":              advInt(cfg.Advanced, "kcp_tti", 50),
			"uplinkCapacity":   advInt(cfg.Advanced, "kcp_up", 5),
			"downlinkCapacity": advInt(cfg.Advanced, "kcp_down", 20),
			"congestion":       advBool(cfg.Advanced, "kcp_congestion", false),
			"readBufferSize":   advInt(cfg.Advanced, "kcp_read_buf", 2),
			"writeBufferSize":  advInt(cfg.Advanced, "kcp_write_buf", 2),
		}

		ss["kcpSettings"] = kcp
	case "http":

		h2 := map[string]interface{}{
			"path": cfg.Transport.Path,
		}
		if host := strings.TrimSpace(cfg.Transport.Host); host != "" {
			var hosts []string
			for _, h := range strings.Split(host, ",") {
				if h = strings.TrimSpace(h); h != "" {
					hosts = append(hosts, h)
				}
			}
			if len(hosts) > 0 {
				h2["host"] = hosts
			}
		}
		ss["httpSettings"] = h2
	case "quic":
		quic := map[string]interface{}{
			"security": firstNonEmpty(strings.TrimSpace(cfg.Transport.Host),
				strings.TrimSpace(cfg.Transport.Path), "none"),
			"key": advStr(cfg.Advanced, "quic_key", ""),
			"header": map[string]interface{}{
				"type": firstNonEmpty(advStr(cfg.Advanced, "quic_header", "none"), "none"),
			},
		}
		ss["quicSettings"] = quic
	case "hysteria":

		hy := map[string]interface{}{
			"version": 2,
			"auth":    cfg.Auth.Password,
		}
		if adv := advInt(cfg.Advanced, "hysteria_udp_idle", 0); adv >= 2 && adv <= 600 {
			hy["udpIdleTimeout"] = adv
		}
		ss["hysteriaSettings"] = hy
	}

	if cfg.Transport.Security == "tls" {

		tlsm := map[string]interface{}{
			"serverName":  cfg.Server.SNI,
			"fingerprint": cfg.Transport.Fingerprint,
			"alpn":        cfg.Transport.ALPN,
		}

		if allowInsecureTLS(cfg) {
			if sni := strings.TrimSpace(cfg.Server.SNI); sni != "" &&
				!strings.EqualFold(sni, cfg.Server.Host) &&
				cfg.Server.Host != "" && cfg.Server.Port > 0 {
				if pins, err := probeCertPins(resolveEndpoint(cfg, cfg.Server.Host),
					cfg.Server.Port, sni); err == nil {
					tlsm["pinnedPeerCertSha256"] = pinChainValue(pins)
					Tracef("[xray] SNI fronting %s!=%s: cert chain pinned", sni, cfg.Server.Host)
				} else {
					tlsm["verifyPeerCertByName"] = cfg.Server.Host
					Warnf("xray", "fronting cert probe %s via %s failed: %v (fallback: cert pinned by name %s)",
						sni, cfg.Server.Host, err, cfg.Server.Host)
				}
			}
		} else {
			Tracef("[xray] Allow Insecure=false: strict TLS verification, no pinning")
		}
		ss["tlsSettings"] = tlsm
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

func isIPLiteral(addr string) bool {
	return net.ParseIP(strings.TrimSpace(addr)) != nil
}

func isLoopback(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	return ip != nil && ip.IsLoopback()
}

func resolveDialAddr(cfg *config.TunnelConfig, addr string) string {
	return addr
}

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

func probeCertPins(addr string, port int, sni string) ([]string, error) {
	serverName := sni
	if serverName == "" || isIPLiteral(serverName) {
		serverName = addr
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}

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

func probeCertPinsViaHTTPProxy(proxyAddr string, proxyPort int, target string, sni string, headers map[string]string) ([]string, error) {
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
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", authority)
	hostSent := false
	for k, v := range headers {
		if strings.EqualFold(k, "host") {
			hostSent = true
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if !hostSent {
		fmt.Fprintf(&b, "Host: %s\r\n", authority)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
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
		h := hex.EncodeToString(sum[:])
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

func pinChainValue(pins []string) string {
	return strings.Join(pins, ",")
}

func httpProxyDialTarget(ob map[string]interface{}) (addr string, port int, headers map[string]string, ok bool) {
	proto, _ := ob["protocol"].(string)
	if proto != "http" {
		return "", 0, nil, false
	}
	addr, port = outboundDialTarget(ob)
	if addr == "" || port <= 0 {
		return "", 0, nil, false
	}
	if s, sok := ob["settings"].(map[string]interface{}); sok {
		if hm, hok := s["headers"].(map[string]interface{}); hok {
			headers = map[string]string{}
			for k, v := range hm {
				if vs, ok := v.(string); ok {
					headers[k] = vs
				}
			}
		}
	}
	return addr, port, headers, true
}

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
	if !allowInsecureTLS(cfg) {

		Tracef("[xray] stored outbound: Allow Insecure=false, cert pinning skipped")
		return
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

		tlsm["pinnedPeerCertSha256"] = pinChainValue(pins)
		Tracef("[xray] pinned cert chain for %s:%d (%d in chain)", addr, port, len(pins))
	}
}

func csvList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func IsWireGuard(cfg *config.TunnelConfig) bool {
	return advStr(cfg.Advanced, "wg_secret_key", "") != "" || advStr(cfg.Advanced, "wg_peer_public_key", "") != ""
}

func BuildWireGuardOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	addr = resolveEndpoint(cfg, addr)
	addresses := csvList(advStr(cfg.Advanced, "wg_address", ""))
	if len(addresses) == 0 {

		addresses = []string{"10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"}
	}
	allowed := csvList(advStr(cfg.Advanced, "wg_allowed_ips", ""))
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	peer := map[string]interface{}{
		"endpoint":   fmt.Sprintf("%s:%d", addr, port),
		"publicKey":  advStr(cfg.Advanced, "wg_peer_public_key", ""),
		"allowedIPs": allowed,
	}
	if psk := advStr(cfg.Advanced, "wg_pre_shared_key", ""); psk != "" {
		peer["preSharedKey"] = psk
	}
	if ka := advInt(cfg.Advanced, "wg_keep_alive", 0); ka > 0 {
		peer["keepAlive"] = ka
	}
	settings := map[string]interface{}{
		"secretKey": advStr(cfg.Advanced, "wg_secret_key", ""),
		"address":   addresses,
		"peers":     []map[string]interface{}{peer},
	}
	if mtu := advInt(cfg.Advanced, "wg_mtu", 0); mtu > 0 {
		settings["mtu"] = mtu
	}
	if res := csvList(advStr(cfg.Advanced, "wg_reserved", "")); len(res) == 3 {
		b := make([]int, 3)
		ok := true
		for i, p := range res {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				ok = false
				break
			}
			b[i] = n
		}
		if ok {
			settings["reserved"] = b
		}
	}
	noKernel := true
	if s := advStr(cfg.Advanced, "wg_no_kernel_tun", ""); s == "false" || s == "0" {
		noKernel = false
	}
	settings["noKernelTun"] = noKernel
	if dns := csvList(advStr(cfg.Advanced, "wg_remote_dns", "")); len(dns) > 0 {
		settings["remoteDNS"] = dns
	}
	return map[string]interface{}{
		"protocol": "wireguard",
		"tag":      "proxy",
		"settings": settings,
	}
}

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

func BuildHttpOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	addr = resolveDialAddr(cfg, addr)
	server := map[string]interface{}{"address": addr, "port": port}
	if u := strings.TrimSpace(cfg.Auth.Username); u != "" {
		server["users"] = []map[string]interface{}{
			{"user": u, "pass": cfg.Auth.Password},
		}
	}
	return map[string]interface{}{
		"protocol":       "http",
		"tag":            "proxy",
		"settings":       map[string]interface{}{"servers": []map[string]interface{}{server}},
		"streamSettings": buildStreamSettings(cfg, addr),
	}
}

func BuildSocksOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	addr = resolveDialAddr(cfg, addr)
	server := map[string]interface{}{"address": addr, "port": port}
	if u := strings.TrimSpace(cfg.Auth.Username); u != "" {
		server["users"] = []map[string]interface{}{
			{"user": u, "pass": cfg.Auth.Password},
		}
	}
	return map[string]interface{}{
		"protocol":       "socks",
		"tag":            "proxy",
		"settings":       map[string]interface{}{"servers": []map[string]interface{}{server}},
		"streamSettings": buildStreamSettings(cfg, addr),
	}
}

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

	var inbounds []interface{}
	for _, v := range asList(m["inbounds"]) {
		if im, ok := v.(map[string]interface{}); ok && im["protocol"] == "socks" {
			continue
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
		if _, has := tlsm["pinnedPeerCertChainSha256"]; has {
			continue
		}
		addr, port := outboundDialTarget(ob)
		if addr == "" || port <= 0 || isLoopback(addr) {
			continue
		}
		sni, _ := tlsm["serverName"].(string)
		target := net.JoinHostPort(addr, strconv.Itoa(port))

		byNameFallback := func(context string, probeErr error) {
			if sni != "" && !strings.EqualFold(sni, addr) && !isIPLiteral(addr) {
				tlsm["verifyPeerCertByName"] = addr
				Warnf("xray", "full-config TLS probe %s failed: %v (fallback: cert pinned by name %s)",
					context, probeErr, addr)
			} else {
				Warnf("xray", "full-config TLS probe %s failed: %v (strict verification)",
					context, probeErr)
			}
		}

		var pins []string
		var err error

		if ps, ok := ob["proxySettings"].(map[string]interface{}); ok {
			if tag, _ := ps["tag"].(string); tag != "" {
				if hop, ok2 := byTag[tag]; ok2 {
					if pAddr, pPort, headers, isHTTP := httpProxyDialTarget(hop); isHTTP {
						pins, err = probeCertPinsViaHTTPProxy(pAddr, pPort, target, sni, headers)
						if err != nil {
							byNameFallback(fmt.Sprintf("%s via proxy %s:%d", target, pAddr, pPort), err)
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
				byNameFallback(fmt.Sprintf("%s:%d", addr, port), err)
				continue
			}
			Tracef("[xray] full-config: pinned cert chain for %s:%d", addr, port)
		}
		tlsm["pinnedPeerCertSha256"] = pinChainValue(pins)
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

func TunnelOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {

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

				addr = resolveDialAddr(cfg, addr)
				rewriteOutboundAddr(m, addr, port)
				patchStoredTLS(m, cfg, addr, port)
				ob = m
			}
		}
	}
	if ob == nil {
		if IsWireGuard(cfg) {
			ob = BuildWireGuardOutbound(cfg, addr, port)
		} else {
			ob = BuildVlessOutbound(cfg, addr, port)
		}
	}
	applyOutboundChainOptions(ob, cfg)
	return ob
}

func SlowDNSOutbound(cfg *config.TunnelConfig, fwdPort int) map[string]interface{} {
	ob := TunnelOutbound(cfg, "127.0.0.1", fwdPort)
	rewriteOutboundAddr(ob, "127.0.0.1", fwdPort)
	return ob
}

func rewriteOutboundAddr(ob map[string]interface{}, addr string, port int) {
	s, ok := ob["settings"].(map[string]interface{})
	if !ok {
		return
	}

	if ob["protocol"] == "wireguard" {
		for _, p := range asMapList(s["peers"]) {
			p["endpoint"] = net.JoinHostPort(addr, strconv.Itoa(port))
		}
		return
	}
	if _, flat := s["address"]; flat {
		s["address"] = addr
		s["port"] = port
		return
	}
	if rewriteAddrList(s["vnext"], addr, port) {
		return
	}
	rewriteAddrList(s["servers"], addr, port)
}

func asMapList(v interface{}) []map[string]interface{} {
	switch arr := v.(type) {
	case []map[string]interface{}:
		return arr
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(arr))
		for _, it := range arr {
			if m, ok := it.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
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

func applyOutboundChainOptions(ob map[string]interface{}, cfg *config.TunnelConfig) {
	if ob == nil || cfg == nil {
		return
	}
	if tag := proxySettingsTag(cfg); tag != "" {

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

func hasDialerProxy(ob map[string]interface{}) bool {
	ss, ok := ob["streamSettings"].(map[string]interface{})
	if !ok {
		return false
	}
	sockopt, _ := ss["sockopt"].(map[string]interface{})
	_, exists := sockopt["dialerProxy"]
	return exists
}

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

	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name = rest[i+1:]
		rest = rest[:i]
		if un, err := url.PathUnescape(name); err == nil {
			name = un
		}
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i]
	}

	var method, password, host string
	var port int

	if i := strings.LastIndex(rest, "@"); i >= 0 {

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
