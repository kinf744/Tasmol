package pho

// Secrets et constantes sensibles servies au reste de l'app via le .so
// garblé (plus aucun littéral dans le DEX/Java) :
//   - preuve d'appareil anti-clonage (HMAC, remplace le calcul Java)
//   - secret d'installation scellé (pho.id, remplace les préférences XML)
//   - dérivation de l'UUID v4 (remplace la formule Java)
//   - ports d'écoute locaux (relais, UDPGW, manage)
//   - nom du fichier journal
//
// Toutes les chaînes sensibles sont reconstruites par code points (r2) :
// jamais contiguës dans le binaire.

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

// ── Preuve d'appareil (anti-clonage d'UUID) ──────────────────────────────
// proof = HMAC-SHA256(key = SHA-256(ANDROID_ID), msg = uuid), hex minuscule.
// Sortie STRICTEMENT identique à l'ancienne implémentation Java
// (DeviceIdentity.proof) — les preuves déjà épinglées côté serveur restent
// valides.
func DeviceProof(uuid, androidId string) string {
	key := sha256.Sum256([]byte(androidId))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(uuid))
	return hex.EncodeToString(mac.Sum(nil))
}

// ── Secret d'installation scellé (pho.id) ────────────────────────────────
// Remplace le secret d'identité stocké en clair dans les préférences XML :
// scellé AES-256-GCM (clé PBKDF2 600k sur contexte r2 + sel d'installation)
// dans un fichier dédié 0600. Le coffre des comptes (pho.vault) n'est pas
// touché : le secret d'identité survit au logout (VaultClear).
var (
	idFile = r2(112, 104, 111, 46, 105, 100) // "pho.id"
	idMu   sync.Mutex
	idVal  string
)

// identityContext : contexte r2 "pho-id-v1".
func identityContext() []byte {
	return []byte(r2(112, 104, 111, 45, 105, 100, 45, 118, 49))
}

// identityKey dérive la clé AES du fichier identité (cache par sel).
func identityKey(salt []byte) []byte {
	ctx := sha256.Sum256(append(identityContext(), salt...))
	return pbkdf2Key([]byte(r2(112, 104, 111, 45, 105, 100)), ctx[:], vaultKDFIterations, 32)
}

// IdentityEnsure retourne le secret d'installation (32 hex), créé et scellé
// au premier appel. "" si le stockage est indisponible.
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

// IdentityUuid dérive l'UUID v4 de l'appareil :
// uuid = format(SHA-256(secret | ANDROID_ID)), bits version/variante
// positionnés — STRICTEMENT identique à l'ancienne dérivation Java
// (DeviceIdentity.uuidFrom). "" si indisponible (Java retombe alors sur
// son chemin legacy).
func IdentityUuid(androidId string) string {
	s := IdentityEnsure()
	if s == "" {
		return ""
	}
	d := sha256.Sum256([]byte(s + "|" + androidId))
	d[6] = (d[6] & 0x0F) | 0x40 // version 4
	d[8] = (d[8] & 0x3F) | 0x80 // variante RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		d[0:4], d[4:6], d[6:8], d[8:10], d[10:16])
}

// ── Ports d'écoute locaux ────────────────────────────────────────────────
// p2 reconstitue un port depuis deux composants : plus aucun littéral
// "8080"/"7300"/"18080" exploitable par grep dans le DEX.

func p2(hi, lo int) int { return hi*100 + lo }

// PortRelay : relais TCP du partage hotspot (TcpRelay.FIXED_PORT).
func PortRelay() int { return p2(80, 80) }

// PortUdpgw : UDPGW local par défaut (config.yaml).
func PortUdpgw() int { return p2(73, 0) }

// PortManage : port d'administration local par défaut.
func PortManage() int { return p2(180, 80) }

// ── Nom du fichier journal ───────────────────────────────────────────────
// Résolu côté natif pour ne plus laisser le marqueur dans le DEX. La
// constante est partagée Java/Go via le pont : les deux côtés écrivent
// toujours le MÊME fichier.
func LogFileName() string {
	return r2(107, 105, 103, 104, 109, 117, 46, 116, 120, 116) // k*i*g*h*m*u.txt
}

// ── Erreur partagée ──────────────────────────────────────────────────────
var errNotInitialized = errors.New("pho not initialized")
