package tunnel

import (
	"encoding/hex"
	"strings"
	"testing"

	"vpn-app/internal/config"
)

// MTN-style fronting: SNI zero-rated, cert CN = real server host.
// Xray 26.x: pinnedPeerCertSha256 is a STRING of comma-separated hex
// SHA-256 digests (array -> config load aborts; base64 -> never matches).
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
	if _, bad := tlsm["pinnedPeerCertChainSha256"]; bad {
		t.Fatal("pinnedPeerCertChainSha256 key present (unknown to Xray 26.x)")
	}
	pinsStr, ok := tlsm["pinnedPeerCertSha256"].(string)
	if !ok || pinsStr == "" {
		t.Fatalf("expected pinnedPeerCertSha256 string, got %v", tlsm["pinnedPeerCertSha256"])
	}
	for _, h := range strings.Split(pinsStr, ",") {
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			t.Fatalf("pin %q is not 32-byte hex", h)
		}
	}
	t.Logf("pinned chain: %s", pinsStr)

	// Probe failure path: closed port => probe fails => must fall back to
	// verifyPeerCertByName (never strict CA verification, which breaks
	// zero-rated fronting).
	cp := *tc // copy: ne pas muter la config du premier cas
	cp.Server.Port = 9 // discard port: closed
	bad := &cp
	ob = TunnelOutbound(bad, bad.Server.Host, 9)
	ss, _ = ob["streamSettings"].(map[string]interface{})
	tlsm, _ = ss["tlsSettings"].(map[string]interface{})
	if pins, ok2 := tlsm["pinnedPeerCertSha256"].(string); ok2 && pins != "" {
		t.Logf("probe unexpectedly succeeded, pins present")
		return
	}
	name, _ := tlsm["verifyPeerCertByName"].(string) // string CSV en 26.x
	if name != bad.Server.Host {
		t.Fatalf("expected verifyPeerCertByName fallback, got %v", tlsm["verifyPeerCertByName"])
	}
}
