package tunnel

import (
	"testing"

	"vpn-app/internal/config"
)

// MTN-style fronting: SNI zero-rated, cert CN = real server host.
// The generated tlsSettings must use pinnedPeerCertChainSha256 (array),
// never pinnedPeerCertSha256 (string in Xray 26.x -> config load aborts).
func TestFrontingTLSUsesChainPin(t *testing.T) {
	tc := &config.TunnelConfig{
		Name: "MTN 150Mo",
		Type: config.TunnelXray,
	}
	tc.Server.Host = "vlo.kingom.ggff.net"
	tc.Server.Port = 443
	tc.Server.SNI = "mtnplay.com"
	tc.Auth.UUID = "e1cfc587-666d-48d0-b234-e52833d43923"
	tc.Transport.Network = "ws"
	tc.Transport.Security = "tls"
	tc.Transport.Path = "/vless"
	tc.Transport.Host = "vlo.kingom.ggff.net"

	ob := TunnelOutbound(tc, tc.Server.Host, tc.Server.Port)
	ss, _ := ob["streamSettings"].(map[string]interface{})
	tlsm, _ := ss["tlsSettings"].(map[string]interface{})
	if tlsm == nil {
		t.Fatal("no tlsSettings")
	}
	if _, bad := tlsm["pinnedPeerCertSha256"]; bad {
		t.Fatal("legacy pinnedPeerCertSha256 key present (breaks Xray 26.x)")
	}
	pins, ok := tlsm["pinnedPeerCertChainSha256"].([]string)
	if !ok || len(pins) == 0 {
		t.Fatalf("expected pinnedPeerCertChainSha256 pins, got %v", tlsm["pinnedPeerCertChainSha256"])
	}
	t.Logf("pinned %d chain certs", len(pins))

	// Probe failure path: closed port => probe fails => must fall back to
	// verifyPeerCertByName (never strict CA verification, which breaks
	// zero-rated fronting).
	cp := *tc // copy: ne pas muter la config du premier cas
	cp.Server.Port = 9 // discard port: closed
	bad := &cp
	ob = TunnelOutbound(bad, bad.Server.Host, 9)
	ss, _ = ob["streamSettings"].(map[string]interface{})
	tlsm, _ = ss["tlsSettings"].(map[string]interface{})
	if _, badKey := tlsm["pinnedPeerCertSha256"]; badKey {
		t.Fatal("legacy key emitted on fallback path")
	}
	if pins, ok2 := tlsm["pinnedPeerCertChainSha256"].([]string); ok2 && len(pins) > 0 {
		t.Logf("probe unexpectedly succeeded, pins present (%d)", len(pins))
		return
	}
	names, ok2 := tlsm["verifyPeerCertByName"].([]string)
	if !ok2 || len(names) == 0 || names[0] != bad.Server.Host {
		t.Fatalf("expected verifyPeerCertByName fallback, got %v", tlsm["verifyPeerCertByName"])
	}
}
