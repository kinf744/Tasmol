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

func r2(cp ...int32) string { return string(cp) }

var apiHosts = []string{

	r2(104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 105, 45, 118, 49, 46, 107, 105, 110, 103, 111, 109, 46, 103, 103, 102, 102, 46, 110, 101, 116),

	r2(104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 105, 45, 118, 49, 46, 107, 105, 110, 103, 111, 109, 46, 103, 103, 102, 102, 46, 110, 101, 116, 58, 56, 52, 52, 51),
}

var (
	pathRegister = r2(47, 97, 112, 105, 47, 118, 49, 47, 100, 101, 118, 105, 99, 101, 115, 47, 114, 101, 103, 105, 115, 116, 101, 114)
	pathConfigs  = r2(47, 97, 112, 105, 47, 118, 49, 47, 117, 115, 101, 114, 47, 99, 111, 110, 102, 105, 103, 115)
	pathCheck    = r2(47, 97, 112, 105, 47, 118, 49, 47, 100, 101, 118, 105, 99, 101, 115, 47, 99, 104, 101, 99, 107)
)

var storeDir string

func Init(dir string) error {
	if dir == "" {
		return errors.New("empty dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	storeDir = dir

	if loadSalt() == nil {
		return errors.New("cannot create vault salt")
	}

	hardenSelf()
	return nil
}

var (
	pinFile        = r2(112, 104, 111, 46, 112, 105, 110)
	storeFile      = r2(112, 104, 111, 46, 118, 97, 117, 108, 116)
	saltFile       = r2(112, 104, 111, 46, 115, 97, 108, 116)
	procSelfStatus = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 115, 116, 97, 116, 117, 115)
	tracerPidStr   = r2(84, 114, 97, 99, 101, 114, 80, 105, 100, 58)
	devQemuPipe    = r2(47, 100, 101, 118, 47, 113, 117, 109, 117, 95, 112, 105, 112, 101)
	devGoldfish    = r2(47, 100, 101, 118, 47, 103, 111, 108, 100, 102, 105, 115, 104, 95, 112, 105, 112, 101)
)

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

func ResetPin() {
	if storeDir == "" {
		return
	}
	_ = os.Remove(filepath.Join(storeDir, pinFile))
}

func mkTransport(remember bool, base string) *http.Transport {
	key := hostKey(base)
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
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

					return errors.New(r2(115, 101, 114, 118, 101, 117, 114,
						32, 105, 110, 106, 111, 105, 103, 110, 97, 98, 108, 101))

				}
				return nil
			},
		},
		ForceAttemptHTTP2: false,
	}
}

var (
	proxyMu   sync.RWMutex
	proxyAddr string
)

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
			continue
		}
		return m, nil
	}

	return nil, errors.New(r2(115, 101, 114, 118, 101, 117, 114, 32, 105, 110,
		106, 111, 105, 103, 110, 97, 98, 108, 101))
}

func mOK(m map[string]interface{}) bool {

	_, a := m["activated"]
	_, b := m["configs"]
	_, c := m["success"]
	_, d := m["account"]
	return c || b || (a && d)
}

func getJSON(pathQuery string) (map[string]interface{}, error) {
	m, err := getVia(pathQuery, currentProxy())
	if err != nil && currentProxy() != "" {

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

	return nil, errors.New(r2(115, 101, 114, 118, 101, 117, 114, 32, 105, 110,
		106, 111, 105, 103, 110, 97, 98, 108, 101))
}

func Activate(phone, code, uuid, proof string) (string, error) {
	return jsonString(postJSON(uuid, pathRegister, map[string]string{
		"uuid":              uuid,
		"device_install_id": uuid,
		"phone_number":      phone,
		"activation_code":   code,
		"device_proof":      proof,
	}))
}

func FetchConfigs(uuid, code string) (string, error) {
	q := url.Values{"uuid": {uuid}, "code": {code}}.Encode()
	return jsonString(getJSON(pathConfigs + "?" + q))
}

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

const vaultKDFIterations = 600000

func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
}

func storeKey(uuid string, salt []byte) []byte {
	ctx := sha256.Sum256(append([]byte(r2(112, 104, 111, 45, 118, 50)), salt...))
	return pbkdf2Key([]byte(uuid), ctx[:], vaultKDFIterations, 32)
}

func legacyKey(uuid string) []byte {
	salt := sha256.Sum256([]byte(r2(112, 104, 111, 45, 118, 49) + uuid))
	return pbkdf2Key([]byte(uuid), salt[:], 60000, 32)
}

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

func TunPut(uuid, kind, field, value string) error {
	if !tunnelKinds[kind] {
		return errors.New("unknown tunnel kind")
	}
	if !validTunField(field) {
		return errors.New("invalid field name")
	}
	return VaultPut(uuid, "tun."+kind+"."+field, value)
}

func TunGet(uuid, kind, field string) string {
	if !tunnelKinds[kind] || !validTunField(field) {
		return ""
	}
	return VaultGet(uuid, "tun."+kind+"."+field)
}

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

func SaveAccount(uuid, phone, code string) error {
	if err := VaultPut(uuid, "api.phone", phone); err != nil {
		return err
	}
	return VaultPut(uuid, "api.code", code)
}

func LoadAccount(uuid string) string {
	out, _ := json.Marshal(map[string]string{
		"phone": VaultGet(uuid, "api.phone"),
		"code":  VaultGet(uuid, "api.code"),
	})
	return string(out)
}

func ClearAccount(uuid string) error {
	v, _ := storeRead(uuid)
	if v == nil {
		return nil
	}
	delete(v, "api.phone")
	delete(v, "api.code")
	return storeWrite(uuid, v)
}

func SelfCheck() string {
	b, _ := json.Marshal(deepCheck())
	return string(b)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func PEMPinHash(pemText string) string {
	bl, _ := pem.Decode([]byte(pemText))
	if bl == nil {
		return ""
	}
	sum := sha256.Sum256(bl.Bytes)
	return base64.StdEncoding.EncodeToString(sum[:])
}
