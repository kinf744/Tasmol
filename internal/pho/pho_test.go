package pho

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeepCheckShape(t *testing.T) {
	v := deepCheck()
	for _, k := range []string{"traced", "emulator", "frida", "hook", "root", "magisk", "hard"} {
		if _, ok := v[k]; !ok {
			t.Fatalf("missing key %s", k)
		}
	}
}

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
	if _, err := storeOpen(legacyKey("autre-uuid"), data); err == nil {
		t.Fatal("decrypt with wrong uuid must fail")
	}
}

func TestVaultV2SaltRequired(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if err := VaultPut("uuid-v2", "code", "secret-v2"); err != nil {
		t.Fatal(err)
	}
	salt := loadSalt()
	if salt == nil || len(salt) != 32 {
		t.Fatal("salt file missing")
	}
	// Clé v2 (uuid+salt) déchiffre ; la clé v1 (uuid seul) ne doit PAS.
	data, _ := os.ReadFile(dir + "/pho.vault")
	if _, err := storeOpen(storeKey("uuid-v2", salt), data); err != nil {
		t.Fatalf("v2 key must decrypt: %v", err)
	}
	if _, err := storeOpen(legacyKey("uuid-v2"), data); err == nil {
		t.Fatal("legacy key must NOT decrypt a v2 vault")
	}
	// Mauvais salt (autre installation) -> illisible.
	if _, err := storeOpen(storeKey("uuid-v2", make([]byte, 32)), data); err == nil {
		t.Fatal("foreign salt must fail")
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

func TestMapLineSuspicious(t *testing.T) {
	hits := []string{
		"/data/local/tmp/re.frida.server/frida-agent.so",
		"7f2a1000-7f2a2000 r-xp 0 /data/local/tmp/linjector",
		"/data/app/libgum.so",
		"gum-js-loop",
		"/system/lib/libsubstrate.so",
		"/system/lib/libxposed_art.so",
	}
	for _, h := range hits {
		if !mapLineSuspicious(h) {
			t.Fatalf("must detect: %s", h)
		}
	}
	clean := []string{
		"/apex/com.android.runtime/lib64/bionic/libc.so",
		"/data/app/com.borum.vpn/lib/arm/libgojni.so",
		"/system/lib64/libbinder.so",
	}
	for _, c := range clean {
		if mapLineSuspicious(c) {
			t.Fatalf("false positive: %s", c)
		}
	}
}

func TestProbeFridaPorts(t *testing.T) {
	// Aucun frida-server sur la machine de test : aucun hit.
	if hits := probeFridaPorts(); len(hits) != 0 {
		t.Fatalf("unexpected hits: %v", hits)
	}
}

func TestDeviceProofMatchesJava(t *testing.T) {
	// Vecteurs figés (référence Python/Java) : la sortie DOIT rester
	// identique à l'ancienne implémentation Java — les preuves épinglées
	// côté serveur le exigent.
	got := DeviceProof("a1b2c3d4-e5f6-4a1b-8c2d-9e0f1a2b3c4d", "1234567890abcdef")
	if got != "0b7c05128dc8127079ef6a02aa0077b86947c3b8eeaacd0ca03a606730932bf7" {
		t.Fatalf("proof vector mismatch: %s", got)
	}
	// ANDROID_ID vide : clé = SHA-256("") (82d2… — référence Python).
	got = DeviceProof("u", "")
	if got != "82d206e486c4629c17ae9322b2bc1251df69500dce75d0b233f364c076068778" {
		t.Fatalf("empty aid proof mismatch: %s", got)
	}
}

func TestIdentityUuidVector(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	// Vecteur figé (référence Python) : secret imposé via IdentityEnsure
	// puis uuid dérivé — format v4 et valeur identiques à l'ancienne
	// formule Java (SHA-256(secret|aid), nibbles version/variante).
	s := IdentityEnsure()
	if len(s) != 32 {
		t.Fatalf("secret must be 32 hex chars: %q", s)
	}
	// Réécrivons pho.id avec un secret connu pour vérifier le vecteur.
	salt := loadSalt()
	known := "0123456789abcdef0123456789abcdef"
	enc, err := sealWithKey(identityKey(salt), []byte(known))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, idFile), enc, 0600); err != nil {
		t.Fatal(err)
	}
	idVal = "" // invalide le cache pour forcer la relecture
	if got := IdentityEnsure(); got != known {
		t.Fatalf("identity read-back: got %q", got)
	}
	u := IdentityUuid("1234567890abcdef")
	if u != "0809c47f-76c4-415c-864c-9c7f05b13065" {
		t.Fatalf("uuid vector mismatch: %s", u)
	}
	// Stable sur appels répétés (cache).
	if u2 := IdentityUuid("1234567890abcdef"); u2 != u {
		t.Fatal("identity uuid must be stable")
	}
	// Un autre appareil (autre ANDROID_ID) dérive un uuid différent.
	if IdentityUuid("ffffffffffffffff") == u {
		t.Fatal("different device must derive a different uuid")
	}
}

func TestPortsObfuscated(t *testing.T) {
	if PortRelay() != 8080 || PortUdpgw() != 7300 || PortManage() != 18080 {
		t.Fatalf("ports: %d %d %d", PortRelay(), PortUdpgw(), PortManage())
	}
}

func TestLogFileNameShared(t *testing.T) {
	// Le nom doit correspondre à celui utilisé par le fichier Java
	// (Bridge PhoLogFileName) : format <nom>.txt, non vide.
	n := LogFileName()
	if n == "" || filepath.Ext(n) != ".txt" {
		t.Fatalf("bad log file name: %q", n)
	}
}

func TestVaultCacheConsistency(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	const uuid = "uuid-cache"
	// Écriture -> cache -> lecture (depuis le cache) -> fichier toujours chiffré.
	if err := VaultPut(uuid, "k1", "v1"); err != nil {
		t.Fatal(err)
	}
	if got := VaultGet(uuid, "k1"); got != "v1" {
		t.Fatalf("cached read: got %q", got)
	}
	data, _ := os.ReadFile(dir + "/pho.vault")
	if len(data) == 0 || string(data[:1]) == "{" {
		t.Fatal("vault file must remain encrypted")
	}
	// Écritures successives : le cache suit la dernière valeur.
	if err := VaultPut(uuid, "k1", "v2"); err != nil {
		t.Fatal(err)
	}
	if got := VaultGet(uuid, "k1"); got != "v2" {
		t.Fatalf("cache staleness: got %q", got)
	}
	// Clear : cache invalidé, lecture vide, fichier parti.
	VaultClear(uuid)
	if got := VaultGet(uuid, "k1"); got != "" {
		t.Fatalf("clear must invalidate cache: got %q", got)
	}
	if _, err := os.Stat(dir + "/pho.vault"); !os.IsNotExist(err) {
		t.Fatal("vault file must be removed")
	}
	// Isolation inter-uuid conservée avec le cache.
	if err := VaultPut("u-a", "k", "a"); err != nil {
		t.Fatal(err)
	}
	if err := VaultPut("u-b", "k", "b"); err != nil {
		t.Fatal(err)
	}
	if VaultGet("u-a", "k") != "a" || VaultGet("u-b", "k") != "b" {
		t.Fatal("cross-uuid isolation broken with cache")
	}
}
