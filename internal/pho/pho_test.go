package pho

import (
	"os"
	"strings"
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
	if _, err := storeOpen("autre-uuid", data); err == nil {
		t.Fatal("decrypt with wrong uuid must fail")
	}
}

func TestTunnelSecretsAndAccount(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	const uuid = "uuid-tun"

	// Secrets de tunnels (hysteria, ssh, xray)
	if err := TunPut(uuid, "hysteria", "auth", "hyp3r-secret"); err != nil {
		t.Fatal(err)
	}
	if err := TunPut(uuid, "ssh", "pass", "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	if err := TunPut(uuid, "xray", "uuid", "cfe75234-b0d9-477d-b30f-9d24654b2487"); err != nil {
		t.Fatal(err)
	}
	if got := TunGet(uuid, "hysteria", "auth"); got != "hyp3r-secret" {
		t.Fatalf("hysteria auth: got %q", got)
	}
	if got := TunGet(uuid, "ssh", "pass"); got != "s3cr3t" {
		t.Fatalf("ssh pass: got %q", got)
	}
	if got := TunGet(uuid, "xray", "uuid"); got == "" {
		t.Fatal("xray uuid missing")
	}
	// kind / field invalides rejetés
	if err := TunPut(uuid, "rdp", "pass", "x"); err == nil {
		t.Fatal("unknown kind must fail")
	}
	if err := TunPut(uuid, "ssh", "Bad Field", "x"); err == nil {
		t.Fatal("invalid field must fail")
	}
	// Clear d'un tunnel seulement
	if err := TunClear(uuid, "ssh"); err != nil {
		t.Fatal(err)
	}
	if got := TunGet(uuid, "ssh", "pass"); got != "" {
		t.Fatal("ssh secrets must be cleared")
	}
	if got := TunGet(uuid, "xray", "uuid"); got == "" {
		t.Fatal("xray secrets must survive TunClear(ssh)")
	}

	// Credentials API
	if err := SaveAccount(uuid, "+237699000000", "123456"); err != nil {
		t.Fatal(err)
	}
	got := LoadAccount(uuid)
	if got == "" || !strings.Contains(got, "+237699000000") || !strings.Contains(got, "123456") {
		t.Fatalf("LoadAccount: %s", got)
	}
	if err := ClearAccount(uuid); err != nil {
		t.Fatal(err)
	}
	if out := LoadAccount(uuid); strings.Contains(out, "237699") {
		t.Fatalf("account must be cleared: %s", out)
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
