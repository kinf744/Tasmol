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
	savePin("AAAA")
	if loadPin() != "AAAA" {
		t.Fatal("pin not persisted")
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
