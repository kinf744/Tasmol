package pho

import (
	"os"
	"testing"
)

func TestVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if err := VaultPut("uuid-test", "code", "secret"); err != nil {
		t.Fatal(err)
	}
	if got := VaultGet("uuid-test", "code"); got != "secret" {
		t.Fatalf("got %q", got)
	}
	// mauvaise clé (autre uuid) -> illisible
	data, _ := os.ReadFile(dir + "/pho.vault")
	if len(data) == 0 {
		t.Fatal("vault empty")
	}
	if _, err := vaultDecrypt("autre-uuid", data); err == nil {
		t.Fatal("decrypt with wrong uuid must fail")
	}
}

func TestPinPersist(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	pins := loadPins()
	pins["api-v1.kingom.ggff.net:443"] = "AAAA"
	savePins(pins)
	if loadPins()["api-v1.kingom.ggff.net:443"] != "AAAA" {
		t.Fatal("pin not persisted")
	}
	// Rotation tolérée : un autre endpoint a son propre pin.
	pins = loadPins()
	pins["api-v1.kingom.ggff.net:8443"] = "BBBB"
	savePins(pins)
	got := loadPins()
	if got["api-v1.kingom.ggff.net:443"] != "AAAA" || got["api-v1.kingom.ggff.net:8443"] != "BBBB" {
		t.Fatal("per-endpoint pins must coexist")
	}
}

func TestHostKey(t *testing.T) {
	if hostKey("https://api-v1.kingom.ggff.net") != "api-v1.kingom.ggff.net:443" {
		t.Fatal("https default port")
	}
	if hostKey("https://api-v1.kingom.ggff.net:8443") != "api-v1.kingom.ggff.net:8443" {
		t.Fatal("explicit port")
	}
	if hostKey("http://api-v1.kingom.ggff.net:9090") != "api-v1.kingom.ggff.net:9090" {
		t.Fatal("http port")
	}
}

func TestEndpointsObfuscated(t *testing.T) {
	if len(apiHosts) == 0 || apiHosts[0] == "" {
		t.Fatal("empty hosts")
	}
	if pathRegister[0] != '/' {
		t.Fatal("bad path")
	}
}
