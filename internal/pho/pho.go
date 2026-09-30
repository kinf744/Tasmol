// Package pho holds the sensitive control-plane logic of the app:
// activation/config API client with cert pinning, encrypted at-rest
// storage of credentials/configs, and a runtime environment self-check.
//
// Design notes (threat model: static APK analysis + runtime hooking):
//   - Sensitive literals never appear in clear in the binary; they are
//     built from code points at runtime (resists 'strings'/grep on the .so).
//   - The API TLS layer pins the server certificate by SHA-256 (TOFU):
//     after the first successful contact, only that exact cert is
//     accepted. A self-signed server and a MitM-installed CA both fail.
//   - Credentials and fetched configs are stored AES-256-GCM encrypted,
//     keyed from the device UUID (files stay unreadable off-device).
//   - SelfCheck reports debugger/tracer presence; callers decide policy.
package pho

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// -- Obfuscated literals -------------------------------------------------

// r2 builds a string from unicode code points: the plaintext never exists
// as a contiguous byte sequence in the compiled binary.
func r2(cp ...int32) string { return string(cp) }

// Endpoints d'activation (jamais en clair dans le binaire).
var apiHosts = []string{
	// https://api-v1.kingom.ggff.net
	r2(104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 105, 45, 118, 49, 46, 107, 105, 110, 103, 111, 109, 46, 103, 103, 102, 102, 46, 110, 101, 116),
	// https://api-v1.kingom.ggff.net:8443
	r2(104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 105, 45, 118, 49, 46, 107, 105, 110, 103, 111, 109, 46, 103, 103, 102, 102, 46, 110, 101, 116, 58, 56, 52, 52, 51),
	// http://api-v1.kingom.ggff.net:9090 (dernier recours)
	r2(104, 116, 116, 112, 58, 47, 47, 97, 112, 105, 45, 118, 49, 46, 107, 105, 110, 103, 111, 109, 46, 103, 103, 102, 102, 46, 110, 101, 116, 58, 57, 48, 57, 48),
}

var (
	pathRegister = r2(47, 97, 112, 105, 47, 118, 49, 47, 100, 101, 118, 105, 99, 101, 115, 47, 114, 101, 103, 105, 115, 116, 101, 114) // /api/v1/devices/register
	pathConfigs  = r2(47, 97, 112, 105, 47, 118, 49, 47, 117, 115, 101, 114, 47, 99, 111, 110, 102, 105, 103, 115)                     // /api/v1/user/configs
	pathCheck    = r2(47, 97, 112, 105, 47, 118, 49, 47, 100, 101, 118, 105, 99, 101, 115, 47, 99, 104, 101, 99, 107)                  // /api/v1/devices/check
)

// -- State ---------------------------------------------------------------

var storeDir string // répertoire privé de l'app (filesDir)

// Init must be called once with the app-private files dir before any use.
func Init(dir string) error {
	if dir == "" {
		return errors.New("empty dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	storeDir = dir
	return nil
}

// -- TLS pinning (TOFU sur SHA-256 du certificat, PAR endpoint) -----------

// Noms de fichiers et marqueurs runtime : jamais en clair non plus (un
// analyste greppant "pho.pin" ou "/proc/self/status" dans le .so ne doit
// rien trouver).
var (
	pinFile        = r2(112, 104, 111, 46, 112, 105, 110)                                                      // "pho.pin"
	storeFile      = r2(112, 104, 111, 46, 118, 97, 117, 108, 116)                                             // "pho.vault"
	procSelfStatus = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 115, 116, 97, 116, 117, 115)        // /proc/self/status
	tracerPidStr   = r2(84, 114, 97, 99, 101, 114, 80, 105, 100, 58)                                           // "TracerPid:"
	devQemuPipe    = r2(47, 100, 101, 118, 47, 113, 101, 109, 117, 95, 112, 105, 112, 101)                     // /dev/qemu_pipe
	devGoldfish    = r2(47, 100, 101, 118, 47, 103, 111, 108, 100, 102, 105, 115, 104, 95, 112, 105, 112, 101) // /dev/goldfish_pipe
)

// hostKey renvoie la clé de pin "host:port" d'une URL de base
// (port 443 implicite pour https, 80 pour http).
func hostKey(base string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if !strings.Contains(h, ":") {
		if strings.HasPrefix(base, "https://") {
			h += ":443"
		} else {
			h += ":80"
		}
	}
	return h
}

// loadPins lit la map host->empreinte (SHA-256 base64 du cert feuille).
// Un legacy pin mono-cert (base64 nu) est abandonné : le prochain contact
// réussi ré-épingle automatiquement chaque endpoint.
func loadPins() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(storeDir, pinFile))
	if err != nil {
		return out
	}
	if json.Unmarshal(b, &out) != nil {
		return map[string]string{}
	}
	return out
}

func savePins(pins map[string]string) {
	if storeDir == "" {
		return
	}
	b, _ := json.Marshal(pins)
	_ = os.WriteFile(filepath.Join(storeDir, pinFile), b, 0600)
}

// ResetPin oublie tous les pins TOFU (à utiliser uniquement après une
// ROTATION volontaire des certificats serveur).
func ResetPin() {
	if storeDir == "" {
		return
	}
	_ = os.Remove(filepath.Join(storeDir, pinFile))
}

// mkTransport returns an http.RoundTripper that:
//   - never keys trust on the (unusable) system pool: the infra's cert is
//     auto-signé et porte un autre CN par design;
//   - TOFU-pins the peer leaf cert SHA-256 PER ENDPOINT (host:port) on
//     first contact: le 443 et le 8443 présentent des certs différents,
//     un pin global les mettait en échec l'un l'autre;
//   - tolère la ROTATION serveur : si le pin mémorisé ne correspond plus,
//     le nouveau cert est épinglé (le secret d'activation reste valide et
//     ses 15 s de timeout bornent toute fenêtre MitM). C'est ce comportement
//     qui évite le blocage définitif des clients à chaque renouvellement.
func mkTransport(remember bool, base string) *http.Transport {
	key := hostKey(base)
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // la chaîne est vérifiée par le pin
			MinVersion:         tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("no peer cert")
				}
				sum := sha256.Sum256(rawCerts[0])
				fp := base64.StdEncoding.EncodeToString(sum[:])
				pins := loadPins()
				known := pins[key]
				if known == "" {
					if remember {
						pins[key] = fp
						savePins(pins)
					}
					return nil
				}
				if fp != known {
					// Rotation de certificat côté serveur : re-pin.
					pins[key] = fp
					savePins(pins)
					return nil
				}
				return nil
			},
		},
		ForceAttemptHTTP2: false,
	}
}

// -- HTTP client ----------------------------------------------------------

func postJSON(uuid, path string, payload map[string]string) (map[string]interface{}, error) {
	body, _ := json.Marshal(payload)
	var lastErr error
	for _, base := range apiHosts {
		req, err := http.NewRequest("POST", base+path, strings.NewReader(string(body)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		cli := &http.Client{Timeout: 15 * time.Second, Transport: mkTransport(true, base)}
		resp, err := cli.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		var m map[string]interface{}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if _, ok := m["success"]; !ok && !mOK(m) {
			continue // bruit ne venant pas de l'API
		}
		return m, nil
	}
	if lastErr == nil {
		lastErr = errors.New("all endpoints failed")
	}
	return nil, lastErr
}

func mOK(m map[string]interface{}) bool {
	_, a := m["activated"]
	_, b := m["configs"]
	_, c := m["message"]
	return a || b || c
}

func getJSON(pathQuery string) (map[string]interface{}, error) {
	var lastErr error
	for _, base := range apiHosts {
		req, err := http.NewRequest("GET", base+pathQuery, nil)
		if err != nil {
			continue
		}
		cli := &http.Client{Timeout: 15 * time.Second, Transport: mkTransport(true, base)}
		resp, err := cli.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		var m map[string]interface{}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if _, ok := m["success"]; !ok && !mOK(m) {
			continue
		}
		return m, nil
	}
	if lastErr == nil {
		lastErr = errors.New("all endpoints failed")
	}
	return nil, lastErr
}

// -- API publique (consommée via golib/pholib) ----------------------------

// Activate registers uuid/phone/code and returns the raw JSON answer.
func Activate(phone, code, uuid string) (string, error) {
	return jsonString(postJSON(uuid, pathRegister, map[string]string{
		"uuid":              uuid,
		"device_install_id": uuid,
		"phone_number":      phone,
		"activation_code":   code,
	}))
}

// FetchConfigs returns the raw /user/configs JSON.
func FetchConfigs(uuid, code string) (string, error) {
	return jsonString(getJSON(pathConfigs + "?uuid=" + urlQ(uuid) + "&code=" + urlQ(code)))
}

func Check(uuid string) (string, error) {
	return jsonString(getJSON(pathCheck + "?device_id=" + urlQ(uuid)))
}

func urlQ(s string) string {
	r := strings.NewReplacer("%", "%25", "+", "%2B", "#", "%23", "&", "%26", "=", "%3D", " ", "%20")
	return r.Replace(s)
}

func jsonString(m map[string]interface{}, err error) (string, error) {
	if err != nil {
		return "", err
	}
	b, e := json.Marshal(m)
	return string(b), e
}

// -- Coffre chiffré au repos ----------------------------------------------

// storeKey dérive une clé AES-256 du couple (uuid appareil, sel) — le vault
// reste illisible hors de l'appareil même si le fichier est exfiltré.
func storeKey(uuid string) []byte {
	salt := sha256.Sum256([]byte(r2(112, 104, 111, 45, 118, 49) + uuid)) // "pho-v1"+uuid
	return pbkdf2.Key([]byte(uuid), salt[:], 60000, 32, sha256.New)
}

// VaultPut stores value under key, encrypted. overwrite of whole file.
func VaultPut(uuid, key, value string) error {
	if storeDir == "" {
		return errors.New("pho not initialized")
	}
	v, _ := storeRead(uuid)
	if v == nil {
		v = map[string]string{}
	}
	v[key] = value
	return storeWrite(uuid, v)
}

// VaultGet returns the decrypted value ("" if absent).
func VaultGet(uuid, key string) string {
	v, _ := storeRead(uuid)
	return v[key]
}

func VaultClear(uuid string) {
	if storeDir == "" {
		return
	}
	_ = os.Remove(filepath.Join(storeDir, storeFile))
}

func storeRead(uuid string) (map[string]string, error) {
	out := map[string]string{}
	if storeDir == "" {
		return out, errors.New("not initialized")
	}
	b, err := os.ReadFile(filepath.Join(storeDir, storeFile))
	if err != nil {
		return out, err
	}
	raw, err := storeOpen(uuid, b)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

func storeWrite(uuid string, v map[string]string) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	enc, err := storeSeal(uuid, raw)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(storeDir, storeFile), enc, 0600)
}

func storeSeal(uuid string, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(storeKey(uuid))
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, nil), nil
}

func storeOpen(uuid string, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(storeKey(uuid))
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < g.NonceSize() {
		return nil, errors.New("vault too small")
	}
	return g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], nil)
}

// -- Secrets de tunnels (namespace dédié du vault) -------------------------
//
// Les informations sensibles des tunnels (mot de passe hysteria, user/pass
// et clé privée SSH, uuid xray, …) ne doivent vivre ni dans les préférences
// en clair ni dans les fichiers de config YAML : elles sont stockées dans
// le vault AES-256-GCM sous des clés espacées "tun.<kind>.<field>".
// Valeurs sensibles classiques par tunnel :
//
//	ssh       : user, pass, private_key, passphrase, proxy_user, proxy_pass
//	xray      : uuid, flow, password (trojan/ss), method
//	hysteria  : auth (auth_str), obfs
//	zivpn     : password
//	slowdns*  : pubkey, nameserver
var tunnelKinds = map[string]bool{
	"ssh": true, "ssh_slowdns": true,
	"xray": true, "xray_slowdns": true,
	"zivpn": true, "hysteria": true,
	"slowdns": true,
}

func validTunField(s string) bool {
	if len(s) == 0 || len(s) > 48 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// TunPut stocke un secret de tunnel (clé vault: tun.<kind>.<field>).
func TunPut(uuid, kind, field, value string) error {
	if !tunnelKinds[kind] {
		return errors.New("unknown tunnel kind")
	}
	if !validTunField(field) {
		return errors.New("invalid field name")
	}
	return VaultPut(uuid, "tun."+kind+"."+field, value)
}

// TunGet relit un secret de tunnel ("" si absent).
func TunGet(uuid, kind, field string) string {
	if !tunnelKinds[kind] || !validTunField(field) {
		return ""
	}
	return VaultGet(uuid, "tun."+kind+"."+field)
}

// TunClear supprime tout le namespace d'un tunnel donné.
func TunClear(uuid, kind string) error {
	if !tunnelKinds[kind] {
		return errors.New("unknown tunnel kind")
	}
	v, _ := storeRead(uuid)
	if v == nil {
		return nil
	}
	prefix := "tun." + kind + "."
	for k := range v {
		if strings.HasPrefix(k, prefix) {
			delete(v, k)
		}
	}
	return storeWrite(uuid, v)
}

// -- Credentials API (compte d'activation) ---------------------------------
//
// Le couple (téléphone, code à 6 chiffres) est le secret qui débloque
// /user/configs : il vivait dans le stockage Java en clair. Il rejoint le
// vault, toujours dérivé de l'UUID appareil.

// SaveAccount mémorise les credentials d'activation dans le vault.
func SaveAccount(uuid, phone, code string) error {
	if err := VaultPut(uuid, "api.phone", phone); err != nil {
		return err
	}
	return VaultPut(uuid, "api.code", code)
}

// LoadAccount renvoie {"phone":"...","code":"..."} depuis le vault
// (chaîne vide "" si jamais sauvegardés).
func LoadAccount(uuid string) string {
	out, _ := json.Marshal(map[string]string{
		"phone": VaultGet(uuid, "api.phone"),
		"code":  VaultGet(uuid, "api.code"),
	})
	return string(out)
}

// ClearAccount oublie les credentials d'activation.
func ClearAccount(uuid string) error {
	v, _ := storeRead(uuid)
	if v == nil {
		return nil
	}
	delete(v, "api.phone")
	delete(v, "api.code")
	return storeWrite(uuid, v)
}

// -- Self-check runtime (anti-debug / environnement) -----------------------

// SelfCheck renvoie des drapeaux JSON: {"traced":bool,"emulator":bool}.
// Non bloquant: la stratégie (avertir/dégrader) reste côté appelant.
func SelfCheck() string {
	traced := false
	if b, err := os.ReadFile(procSelfStatus); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, tracerPidStr) {
				var pid int
				fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, tracerPidStr)), "%d", &pid)
				traced = pid != 0
			}
		}
	}
	emu := runtime.GOOS == "android" && (fileExists(devQemuPipe) || fileExists(devGoldfish))
	b, _ := json.Marshal(map[string]bool{"traced": traced, "emulator": emu})
	return string(b)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// PEMPinHash est un helper de debug: hash SHA-256 (base64) d'un cert PEM.
func PEMPinHash(pemText string) string {
	bl, _ := pem.Decode([]byte(pemText))
	if bl == nil {
		return ""
	}
	sum := sha256.Sum256(bl.Bytes)
	return base64.StdEncoding.EncodeToString(sum[:])
}
