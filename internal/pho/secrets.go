package pho

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func DeviceProof(uuid, androidId string) string {
	key := sha256.Sum256([]byte(androidId))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(uuid))
	return hex.EncodeToString(mac.Sum(nil))
}

var (
	idFile = r2(112, 104, 111, 46, 105, 100)
	idMu   sync.Mutex
	idVal  string
)

func identityContext() []byte {
	return []byte(r2(112, 104, 111, 45, 105, 100, 45, 118, 49))
}

func identityKey(salt []byte) []byte {
	ctx := sha256.Sum256(append(identityContext(), salt...))
	return pbkdf2Key([]byte(r2(112, 104, 111, 45, 105, 100)), ctx[:], vaultKDFIterations, 32)
}

func IdentityEnsure() string {
	idMu.Lock()
	defer idMu.Unlock()
	if storeDir == "" {
		return ""
	}
	if idVal != "" {
		return idVal
	}
	p := filepath.Join(storeDir, idFile)
	if b, err := os.ReadFile(p); err == nil && len(b) > 16 {
		if salt := loadSalt(); salt != nil {
			if raw, err := storeOpen(identityKey(salt), b); err == nil {
				idVal = strings.TrimSpace(string(raw))
			}
		}
	}
	if idVal == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return ""
		}
		idVal = hex.EncodeToString(raw)
		if salt := loadSalt(); salt != nil {
			enc, err := sealWithKey(identityKey(salt), []byte(idVal))
			if err == nil {
				_ = os.WriteFile(p, enc, 0600)
			}
		}
	}
	return idVal
}

func IdentityUuid(androidId string) string {
	s := IdentityEnsure()
	if s == "" {
		return ""
	}
	d := sha256.Sum256([]byte(s + "|" + androidId))
	d[6] = (d[6] & 0x0F) | 0x40
	d[8] = (d[8] & 0x3F) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		d[0:4], d[4:6], d[6:8], d[8:10], d[10:16])
}

func p2(hi, lo int) int { return hi*100 + lo }

func PortRelay() int { return p2(80, 80) }

func PortUdpgw() int { return p2(73, 0) }

func PortManage() int { return p2(180, 80) }

func LogFileName() string {
	return r2(107, 105, 103, 104, 109, 117, 46, 116, 120, 116)
}

var errNotInitialized = errors.New("pho not initialized")
