package tunnel

import (
	"strings"
	"testing"

	"vpn-app/internal/config"
)

// TestBuildWGShimConfig vérifie le pont WG-UDP -> VLESS -> dnstt :
// inbound dokodemo UDP à cible fixe (port WG du serveur) et outbound VLESS
// sur le forward dnstt local.
func TestBuildWGShimConfig(t *testing.T) {
	uuid := "ea4722d8-911e-4074-b7d9-0bfd9840625e"
	cfg, err := BuildWGShimConfig(uuid, 44165, 33777, 443)
	if err != nil {
		t.Fatalf("BuildWGShimConfig: %v", err)
	}
	for _, want := range []string{
		`"dokodemo-door"`, `"network": "udp"`, `"port": 443`,
		`"port": 44165`, `"port": 33777`, `"vless"`, uuid, `"none"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config ne contient pas %q:\n%s", want, cfg)
		}
	}
}

// TestWGEndpointOverriddenByShim : en chaîne SlowDNS, generateXrayConfig doit
// écrire l'endpoint WG = shim local, jamais le vrai serveur (UDP direct).
func TestWGEndpointOverriddenByShim(t *testing.T) {
	tc := NewXraySlowDNSTunnel(&config.TunnelConfig{
		Name: "wgslowdns",
		Server: config.ServerConfig{
			Host: "vlo.example.com", Port: 443,
			Nameserver:  "nv4.example.com",
			DNSResolver: "8.8.8.8:53",
		},
		Auth:    config.AuthConfig{UUID: "ea4722d8-911e-4074-b7d9-0bfd9840625e"},
		Advanced: map[string]interface{}{
			"wg_secret_key":      "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
			"wg_peer_public_key": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
			"wg_peer_endpoint":   "204.152.219.23:39999",
			"slowdns_pubkey":     strings.Repeat("ab", 32),
		},
	})
	tc.pickedShim = 33777
	cfg, err := tc.generateXrayConfig()
	if err != nil {
		t.Fatalf("generateXrayConfig: %v", err)
	}
	if !strings.Contains(cfg, `"127.0.0.1:33777"`) {
		t.Fatalf("endpoint WG doit être le shim local:\n%s", cfg)
	}
	if strings.Contains(cfg, "204.152.219.23:39999") {
		t.Fatalf("l'endpoint direct ne doit pas fuiter en mode slowdns:\n%s", cfg)
	}
}
