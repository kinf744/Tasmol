package tunnel

import (
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
		Tracef("[xray] WARNING endpoint %s unresolvable here, passing through: %v", name, err)
	}
	return addr
}

// probeCertPins opens one throwaway TLS handshake (no verification) and
// hashes the presented chain: the hashes feed Xray 26.x
// "pinnedPeerCertSha256", the supported replacement for the removed
// "allowInsecure", so self-signed / IP-only certs connect.
func probeCertPins(addr string, port int, sni string) ([]string, error) {
	serverName := sni
	if serverName == "" || isIPLiteral(serverName) {
		serverName = addr
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp",
		net.JoinHostPort(addr, strconv.Itoa(port)), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
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
		// Xray 26.x wants a single hex string (the leaf), not an array.
		tlsm["pinnedPeerCertSha256"] = pins[0]
		Tracef("[xray] pinned leaf cert for %s:%d (%d in chain)", addr, port, len(pins))
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

// TunnelOutbound returns the outbound object for an Xray-family tunnel:
// Advanced["outbound_json"] verbatim when present (links, pasted JSON),
// otherwise the structured VLESS builder.
func TunnelOutbound(cfg *config.TunnelConfig, addr string, port int) map[string]interface{} {
	// Domains are unresolvable by the xray child: dial a self-resolved IP.
	addr = resolveEndpoint(cfg, addr)
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
				return m
			}
		}
	}
	return BuildVlessOutbound(cfg, addr, port)
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
