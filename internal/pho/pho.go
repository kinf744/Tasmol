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
	"bytes"
	"context"
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
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/proxy"
)

// -- Obfuscated literals -------------------------------------------------

// r2 builds a string from unicode code points: the plaintext never exists
// as a contiguous byte sequence in the compiled binary.
func r2(cp ...int32) string { return string(cp) }

// Endpoints d'activation (jamais en clair dans le binaire).
// HTTPS uniquement : le fallback http://…:9090 est retiré — il transmettait
// téléphone + code d'activation en clair et permettait l'injection de
// configs par MitM. usesCleartextTraffic=false côté manifeste l'interdit.
var apiHosts = []string{
	// https://api-v1.kingom.ggff.net
	r2(104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 105, 45, 118, 49, 46, 107, 105, 110, 103, 111, 109, 46, 103, 103, 102, 102, 46, 110, 101, 116),
	// https://api-v1.kingom.ggff.net:8443
	r2(104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 105, 45, 118, 49, 46, 107, 105, 110, 103, 111, 109, 46, 103, 103, 102, 102, 46, 110, 101, 116, 58, 56, 52, 52, 51),
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
	// Sel du coffre créé dès l'initialisation (aléatoire, 0600).
	if loadSalt() == nil {
		return errors.New("cannot create vault salt")
	}
	// Protections passives du processus : non-attachable (ptrace), pas de
	// core dump. Idempotent.
	hardenSelf()
	return nil
}

// -- TLS pinning (TOFU sur SHA-256 du certificat, PAR endpoint) -----------

// Noms de fichiers et marqueurs runtime : jamais en clair non plus (un
// analyste greppant "pho.pin" ou "/proc/self/status" dans le .so ne doit
// rien trouver).
var (
	pinFile        = r2(112, 104, 111, 46, 112, 105, 110)                                                      // "pho.pin"
	storeFile      = r2(112, 104, 111, 46, 118, 97, 117, 108, 116)                                             // "pho.vault"
	saltFile       = r2(112, 104, 111, 46, 115, 97, 108, 116)                                                  // "pho.salt"
	procSelfStatus = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 115, 116, 97, 116, 117, 115)        // /proc/self/status
	tracerPidStr   = r2(84, 114, 97, 99, 101, 114, 80, 105, 100, 58)                                           // "TracerPid:"
	devQemuPipe    = r2(47, 100, 101, 118, 47, 113, 117, 109, 117, 95, 112, 105, 112, 101)                     // /dev/qemu_pipe
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

// ResetPin oublie tous les pins TOFU. C'est désormais le MÉCANISME UNIQUE de
// rotation : si le serveur change de certificat, les clients échouent
// (fail-closed) jusqu'à une rotation volontaire via cette fonction.
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
//   - FAIL-CLOSED sur mismatch : un pin connu qui ne correspond plus est
//     refusé (un MitM se présente avec une nouvelle clé). La rotation
//     légitime du certificat serveur passe par ResetPin() côté déploiement
//     — jamais par une acceptation silencieuse, qui annulait toute la
//     protection du pin.
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
					// Message volontairement générique : le détail
					// (pin, MitM, rotation) ne doit pas fuiter vers l'UI.
					return errors.New(r2(115, 101, 114, 118, 101, 117, 114,
						32, 105, 110, 106, 111, 105, 103, 110, 97, 98, 108, 101))
					// "serveur injoignable"
				}
				return nil
			},
		},
		ForceAttemptHTTP2: false,
	}
}

// -- HTTP client ----------------------------------------------------------

// ── Proxy SOCKS local (auto-consommation via son propre VPN) ─────────────
// Le service VPN exclut l'UID de l'app du TUN (anti-boucle) : sans proxy,
// les appels API de l'app sortent par la connexion SOUS-JACENTE — bloquée
// sur certains opérateurs, d'où l'impossibilité d'actualiser sa
// consommation tant que le VPN est actif. SetProxy route ces appels via le
// SOCKS local du tunnel actif (front round-robin ou SOCKS du profil) : la
// requête part À TRAVERS le VPN, avec le même pinning TLS. Repli direct
// automatique si le chemin tunnel échoue.
var (
	proxyMu   sync.RWMutex
	proxyAddr string
)

// SetProxy définit ("" retire) le SOCKS 127.0.0.1 utilisé par l'API.
func SetProxy(addr string) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	proxyAddr = strings.TrimSpace(addr)
}

func currentProxy() string {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return proxyAddr
}

// socksDialer construit un DialContext SOCKS5 (résolution du domaine par le
// tunnel, aucune fuite DNS locale). Retourne nil si le proxy est vide.
func socksDialer(via string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if via == "" {
		return nil
	}
	d, err := proxy.SOCKS5("tcp", via, nil, proxy.Direct)
	if err != nil {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return d.Dial(network, addr)
	}
}

func postJSON(uuid, path string, payload map[string]string) (map[string]interface{}, error) {
	body, _ := json.Marshal(payload)
	m, err := postVia(body, path, currentProxy())
	if err != nil && currentProxy() != "" {
		// Le chemin tunnel a échoué : repli direct (connexion sous-jacente).
		m, err = postVia(body, path, "")
	}
	return m, err
}

func postVia(body []byte, path, via string) (map[string]interface{}, error) {
	for _, base := range apiHosts {
		req, err := http.NewRequest("POST", base+path, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		tr := mkTransport(true, base)
		if d := socksDialer(via); d != nil {
			tr.DialContext = d
		}
		cli := &http.Client{Timeout: 15 * time.Second, Transport: tr}
		resp, err := cli.Do(req)
		if err != nil {
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
	// Erreur volontairement générique : jamais l'URL (domaine des
	// endpoints obfusqués) ni le détail du dial.
	return nil, errors.New(r2(115, 101, 114, 118, 101, 117, 114, 32, 105, 110,
		106, 111, 105, 103, 110, 97, 98, 108, 101)) // "serveur injoignable"
}

func mOK(m map[string]interface{}) bool {
	// Validation stricte : "message" seul est accepté par n'importe qui
	// (portail captif, bruit réseau). Les réponses légitimes de l'API
	// portent toujours "success" (register), "configs" (fetch) ou
	// "activated"+"account" (check — la réponse /devices/check n'a pas de
	// champ success).
	_, a := m["activated"]
	_, b := m["configs"]
	_, c := m["success"]
	_, d := m["account"]
	return c || b || (a && d)
}

func getJSON(pathQuery string) (map[string]interface{}, error) {
	m, err := getVia(pathQuery, currentProxy())
	if err != nil && currentProxy() != "" {
		// Repli direct (voir postJSON).
		m, err = getVia(pathQuery, "")
	}
	return m, err
}

func getVia(pathQuery, via string) (map[string]interface{}, error) {
	for _, base := range apiHosts {
		req, err := http.NewRequest("GET", base+pathQuery, nil)
		if err != nil {
			continue
		}
		tr := mkTransport(true, base)
		if d := socksDialer(via); d != nil {
			tr.DialContext = d
		}
		cli := &http.Client{Timeout: 15 * time.Second, Transport: tr}
		resp, err := cli.Do(req)
		if err != nil {
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
	// Erreur volontairement générique (voir postJSON).
	return nil, errors.New(r2(115, 101, 114, 118, 101, 117, 114, 32, 105, 110,
		106, 111, 105, 103, 110, 97, 98, 108, 101)) // "serveur injoignable"
}

// -- API publique (consommée via golib/pholib) ----------------------------

// Activate registers uuid/phone/code + device proof. Returns the raw JSON answer.
// La preuve d'appareil (HMAC(ANDROID_ID, uuid)) lie l'UUID au matériel :
// un UUID cloné vers un autre appareil est rejeté par le serveur.
func Activate(phone, code, uuid, proof string) (string, error) {
	return jsonString(postJSON(uuid, pathRegister, map[string]string{
		"uuid":              uuid,
		"device_install_id": uuid,
		"phone_number":      phone,
		"activation_code":   code,
		"device_proof":      proof,
	}))
}

// FetchConfigs returns the raw /user/configs JSON.
func FetchConfigs(uuid, code string) (string, error) {
	q := url.Values{"uuid": {uuid}, "code": {code}}.Encode()
	return jsonString(getJSON(pathConfigs + "?" + q))
}

// Check returns the raw /devices/check JSON.
// Check returns the raw /devices/check JSON. La preuve d'appareil
// accompagne l'UUID : un uuid volé sans le matériel correspondant échoue.
func Check(uuid, proof string) (string, error) {
	q := url.Values{"device_id": {uuid}, "proof": {proof}}.Encode()
	return jsonString(getJSON(pathCheck + "?" + q))
}

func jsonString(m map[string]interface{}, err error) (string, error) {
	if err != nil {
		return "", err
	}
	b, e := json.Marshal(m)
	return string(b), e
}

// -- Coffre chiffré au repos ----------------------------------------------

// storeKey dérive une clé AES-256 de (uuid appareil, sel aléatoire par
// installation) : le sel vit dans pho.salt (0600, jamais sauvegardé depuis
// allowBackup=false) — un vol du fichier vault SEUL, ou la connaissance du
// seul UUID (en clair dans les préférences), ne suffit plus à décrypter.
// 600k itérations = recommandation OWASP PBKDF2-HMAC-SHA256 (2024+).
const vaultKDFIterations = 600000

// pbkdf2Key : wrapper unique de dérivation (importe le KDF à un seul endroit).
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
}

func storeKey(uuid string, salt []byte) []byte {
	ctx := sha256.Sum256(append([]byte(r2(112, 104, 111, 45, 118, 50)), salt...)) // "pho-v2"+salt
	return pbkdf2Key([]byte(uuid), ctx[:], vaultKDFIterations, 32)
}

// legacyKey : ancienne clé v1 (sel dérivé du seul uuid, 60k itérations),
// conservée UNIQUEMENT pour la migration silencieuse vers v2.
func legacyKey(uuid string) []byte {
	salt := sha256.Sum256([]byte(r2(112, 104, 111, 45, 118, 49) + uuid)) // "pho-v1"+uuid
	return pbkdf2Key([]byte(uuid), salt[:], 60000, 32)
}

// loadSalt lit (ou crée au premier usage) le sel aléatoire 256 bits du
// coffre. Nil si l'écriture est impossible.
func loadSalt() []byte {
	if storeDir == "" {
		return nil
	}
	p := filepath.Join(storeDir, saltFile)
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return b
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		return nil
	}
	return b
}

// ── Cache mémoire (clé dérivée + coffre déchiffré) ────────────────────────
//
// Sans cache, CHAQUE VaultGet relisait le fichier et recalculait
// PBKDF2(600k) : ~300-700 ms sur armv7, payées sur le thread UI de l'app
// (tick Home 2 s, navigations). Le cache rend les lectures O(1) après le
// premier déchiffrement ; la clé dérivée n'est calculée qu'une fois par
// (uuid, sel). Invalidation : écriture, clear, changement de sel.
var (
	vaultMu    sync.Mutex
	vaultCache = map[string]map[string]string{}
	keyMu      sync.Mutex
	keyCache   = map[string]*keyEntry{}
)

type keyEntry struct {
	salt []byte
	key  []byte
}

// derivedKey retourne la clé AES-256 du coffre pour uuid (cache + sel).
func derivedKey(uuid string) ([]byte, error) {
	salt := loadSalt()
	if salt == nil {
		return nil, errors.New("vault salt unavailable")
	}
	keyMu.Lock()
	defer keyMu.Unlock()
	if e, ok := keyCache[uuid]; ok && bytes.Equal(e.salt, salt) {
		return e.key, nil
	}
	k := storeKey(uuid, salt)
	keyCache[uuid] = &keyEntry{salt: append([]byte(nil), salt...), key: k}
	return k, nil
}

func cloneMap(v map[string]string) map[string]string {
	out := make(map[string]string, len(v))
	for k2, v2 := range v {
		out[k2] = v2
	}
	return out
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

// VaultGet returns the decrypted value ("" if absent). O(1) via cache.
func VaultGet(uuid, key string) string {
	v, _ := storeRead(uuid)
	return v[key]
}

func VaultClear(uuid string) {
	if storeDir == "" {
		return
	}
	_ = os.Remove(filepath.Join(storeDir, storeFile))
	vaultMu.Lock()
	delete(vaultCache, uuid)
	vaultMu.Unlock()
}

func storeRead(uuid string) (map[string]string, error) {
	out := map[string]string{}
	if storeDir == "" {
		return out, errors.New("not initialized")
	}
	// Cache hit : aucune IO, aucun déchiffrement.
	vaultMu.Lock()
	if v, ok := vaultCache[uuid]; ok {
		out = cloneMap(v)
		vaultMu.Unlock()
		return out, nil
	}
	vaultMu.Unlock()

	b, err := os.ReadFile(filepath.Join(storeDir, storeFile))
	if err != nil {
		return out, err
	}
	key, err := derivedKey(uuid)
	if err != nil {
		return out, err
	}
	raw, err := storeOpen(key, b)
	if err != nil {
		// Migration v1 -> v2 : l'ancien coffre (sel dérivé du seul uuid,
		// 60k itérations) est déchiffré puis immédiatement ré-encrypté en
		// v2 (sel aléatoire + 600k itérations).
		raw, err = storeOpen(legacyKey(uuid), b)
		if err != nil {
			return out, err
		}
		if jerr := json.Unmarshal(raw, &out); jerr != nil {
			return out, jerr
		}
		_ = storeWrite(uuid, out)
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	vaultMu.Lock()
	vaultCache[uuid] = cloneMap(out)
	vaultMu.Unlock()
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
	if err := os.WriteFile(filepath.Join(storeDir, storeFile), enc, 0600); err != nil {
		return err
	}
	// Cache mis à jour SEULEMENT après écriture disque réussie.
	vaultMu.Lock()
	vaultCache[uuid] = cloneMap(v)
	vaultMu.Unlock()
	return nil
}

func storeSeal(uuid string, plain []byte) ([]byte, error) {
	key, err := derivedKey(uuid)
	if err != nil {
		return nil, err
	}
	return sealWithKey(key, plain)
}

// sealWithKey scelle avec une clé explicite (coffre comptes OU fichier
// identité — clés dérivées de contextes r2 distincts).
func sealWithKey(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

func storeOpen(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
// SelfCheck exécute les sondes anti-analyse dynamique (Frida/gadget, hooks,
// TracerPid tous threads, émulateur, root/Magisk, ports d'injection) et
// retourne un verdict JSON. Clé "hard" = instrumentation/débogage détecté.
func SelfCheck() string {
	b, _ := json.Marshal(deepCheck())
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
