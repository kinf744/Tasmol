package tunnel

import (
	"encoding/json"
	"testing"

	"vpn-app/internal/config"
)

// jsonInt normalise un nombre issu d'un Unmarshal JSON (float64) en int,
// afin de comparer "version" sans se laisser piéger par le type dynamique.
func jsonInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return -1
}

// Xray 26.x removed kcpSettings.header and kcpSettings.seed; KCPConfig.Build()
// hard-errors when either key is present, which aborts the whole Xray process.
// Every mKCP outbound used to emit "header" unconditionally.
func TestKcpSettingsNeverEmitsRemovedHeaderOrSeed(t *testing.T) {
	cfg := &config.TunnelConfig{
		Name: "mkcp",
		Server: config.ServerConfig{
			Host: "a.com", Port: 443,
		},
		Auth: config.AuthConfig{UUID: "00000000-0000-4000-8000-000000000000"},
		Transport: config.TransportConfig{
			Network: "kcp",
			Seed:    "un-seed",
		},
		Advanced: map[string]interface{}{
			"kcp_header": "srtp",
			"kcp_seed":   "un-seed",
		},
	}

	ss := buildStreamSettings(cfg, "a.com")
	kcp, ok := ss["kcpSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("kcpSettings absent: %#v", ss)
	}
	if _, bad := kcp["header"]; bad {
		t.Error("kcpSettings.header emitted: Xray 26.x refuses to start with it")
	}
	if _, bad := kcp["seed"]; bad {
		t.Error("kcpSettings.seed emitted: Xray 26.x refuses to start with it")
	}
	// The tunables that still exist must survive.
	if kcp["mtu"] == nil {
		t.Error("kcpSettings.mtu missing")
	}
}

// The Xray hysteria outbound uses a FLAT settings.address/settings.port pair,
// unlike vnext[]/servers[]. rewriteOutboundAddr must handle it, otherwise
// editing the host in the editor after import is silently ignored.
func TestRewriteOutboundAddrHysteriaFlatShape(t *testing.T) {
	ob := map[string]interface{}{
		"protocol": "hysteria",
		"settings": map[string]interface{}{
			"version": 2,
			"address": "ancien.example",
			"port":    1081,
		},
	}
	rewriteOutboundAddr(ob, "nouveau.example", 8443)

	s := ob["settings"].(map[string]interface{})
	if s["address"] != "nouveau.example" {
		t.Errorf("address not rewritten: %#v", s["address"])
	}
	if s["port"] != 8443 {
		t.Errorf("port not rewritten: %#v", s["port"])
	}
	if s["version"] != 2 {
		t.Errorf("version clobbered: %#v", s["version"])
	}
}

// A hysteria profile must still yield its SOCKS listen port end-to-end through
// TunnelOutbound, i.e. the manual outbound_json is honoured and the address is
// patched to the resolvable dial endpoint.
func TestHysteriaOutboundKeepsVersionAndAuth(t *testing.T) {
	raw := `{"protocol":"hysteria","tag":"proxy",
	 "settings":{"version":2,"address":"vps.example","port":443},
	 "streamSettings":{"network":"hysteria","security":"tls",
	   "hysteriaSettings":{"version":2,"auth":"motdepasse"},
	   "tlsSettings":{"serverName":"vps.example"}}}`

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	cfg := &config.TunnelConfig{
		Server:    config.ServerConfig{Host: "vps.example", Port: 443},
		Transport: config.TransportConfig{Network: "hysteria", Security: "tls"},
		Advanced:  map[string]interface{}{OutboundJSONKey: m},
	}

	ob := TunnelOutbound(cfg, "vps.example", 443)
	s, _ := ob["settings"].(map[string]interface{})
	// Les valeurs viennent d'un Unmarshal JSON : "version" est un float64,
	// pas un int. On compare numériquement.
	if jsonInt(s["version"]) != 2 {
		t.Errorf("outbound settings.version lost: %#v", s)
	}
	ss, _ := ob["streamSettings"].(map[string]interface{})
	hy, _ := ss["hysteriaSettings"].(map[string]interface{})
	if jsonInt(hy["version"]) != 2 {
		t.Errorf("hysteriaSettings.version lost: %#v", ss)
	}
	if hy["auth"] != "motdepasse" {
		t.Errorf("hysteriaSettings.auth lost: %#v", hy)
	}
	// "hysteria" must be advertised as a supported transport so the UI can
	// offer it and the validator does not reject it.
	var found bool
	for _, tr := range SupportedTransports() {
		if tr == "hysteria" {
			found = true
		}
	}
	if !found {
		t.Error("hysteria missing from SupportedTransports()")
	}
}

// buildStreamSettings must emit a hysteria transport when the network asks for
// it, carrying "version": 2 and the shared password.
func TestBuildStreamSettingsHysteriaTransport(t *testing.T) {
	cfg := &config.TunnelConfig{
		Server:    config.ServerConfig{Host: "vps.example", Port: 443, SNI: "vps.example"},
		Auth:      config.AuthConfig{Password: "motdepasse"},
		Transport: config.TransportConfig{Network: "hysteria", Security: "tls"},
	}

	ss := buildStreamSettings(cfg, "vps.example")
	if ss["network"] != "hysteria" {
		t.Errorf("network = %#v", ss["network"])
	}
	hy, ok := ss["hysteriaSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("hysteriaSettings absent: %#v", ss)
	}
	if hy["version"] != 2 {
		t.Errorf("hysteriaSettings.version = %#v (Xray requires 2)", hy["version"])
	}
	if hy["auth"] != "motdepasse" {
		t.Errorf("hysteriaSettings.auth = %#v", hy["auth"])
	}
	if ss["tlsSettings"] == nil {
		t.Error("tlsSettings absent: Xray requires tls for hysteria")
	}
}
