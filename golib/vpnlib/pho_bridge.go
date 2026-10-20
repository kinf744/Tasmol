package vpnlib

import (
	"vpn-app/internal/pho"
)

// --- libpho: hardened control-plane (see internal/pho) -------------

// PhoInit initializes the vault store. Call once on app start with the
// app-private files dir.
func PhoInit(filesDir string) string {
	if err := pho.Init(filesDir); err != nil {
		return err.Error()
	}
	return ""
}

// PhoSelfCheck returns JSON {"traced":bool,"emulator":bool}.
func PhoSelfCheck() string { return pho.SelfCheck() }

// PhoActivate registers a device. Returns API JSON, or {"error":...}.
// proof = preuve d'appareil HMAC(ANDROID_ID, uuid) — anti-clonage serveur.
func PhoActivate(phone, code, uuid, proof string) string {
	s, err := pho.Activate(phone, code, uuid, proof)
	if err != nil {
		return phoErrJSON(err)
	}
	return s
}

// PhoFetchConfigs returns the configs JSON, or {"error":...}.
func PhoFetchConfigs(uuid, code string) string {
	s, err := pho.FetchConfigs(uuid, code)
	if err != nil {
		return phoErrJSON(err)
	}
	return s
}

// PhoCheck returns the device-check JSON, or {"error":...}.
func PhoCheck(uuid, proof string) string {
	s, err := pho.Check(uuid, proof)
	if err != nil {
		return phoErrJSON(err)
	}
	return s
}

// PhoVaultPut/PhoVaultGet/PhoVaultClear: encrypted at-rest storage.
func PhoVaultPut(uuid, key, value string) string {
	if err := pho.VaultPut(uuid, key, value); err != nil {
		return err.Error()
	}
	return ""
}

func PhoVaultGet(uuid, key string) string { return pho.VaultGet(uuid, key) }

func PhoVaultClear(uuid string) { pho.VaultClear(uuid) }

// PhoResetPin forgets the TLS pin (only for deliberate cert rotation).
func PhoResetPin() { pho.ResetPin() }

// ── Secrets & constantes servies par le natif (plus rien dans le DEX) ────

// PhoDeviceProof calcule la preuve d'appareil anti-clonage dans le .so :
// HMAC-SHA256(SHA-256(androidId), uuid), hex. Sortie identique à l'ancien
// calcul Java (preuves épinglées serveur toujours valides).
func PhoDeviceProof(uuid, androidId string) string { return pho.DeviceProof(uuid, androidId) }

// PhoIdentityEnsure retourne le secret d'installation (32 hex), créé et
// scellé dans pho.id au premier appel (remplace les préférences XML).
func PhoIdentityEnsure() string { return pho.IdentityEnsure() }

// PhoIdentityUuid dérive l'UUID v4 (secret | ANDROID_ID) côté natif.
func PhoIdentityUuid(androidId string) string { return pho.IdentityUuid(androidId) }

// PhoPortRelay : port du relais hotspot (8080).
func PhoPortRelay() int { return pho.PortRelay() }

// PhoPortUdpgw : port UDPGW local par défaut (7300).
func PhoPortUdpgw() int { return pho.PortUdpgw() }

// PhoPortManage : port d'administration local par défaut (18080).
func PhoPortManage() int { return pho.PortManage() }

// PhoLogFileName : nom du fichier journal résolu côté natif (Java et Go
// écrivent toujours le même fichier).
func PhoLogFileName() string { return pho.LogFileName() }

// --- Secrets de tunnels & credentials API (vault chiffré) -------------

// PhoTunPut stores a tunnel secret in the encrypted vault.
// kind: ssh, ssh_slowdns, xray, xray_slowdns, zivpn, hysteria, slowdns.
// Typical fields:
//
//	hysteria: auth, obfs      ssh: user, pass, private_key, passphrase
//	xray: uuid, flow, password, method      zivpn: password
//
// Returns "" on success, or the error message.
func PhoTunPut(uuid, kind, field, value string) string {
	if err := pho.TunPut(uuid, kind, field, value); err != nil {
		return err.Error()
	}
	return ""
}

// PhoTunGet reads a tunnel secret ("" if absent).
func PhoTunGet(uuid, kind, field string) string { return pho.TunGet(uuid, kind, field) }

// PhoTunClear wipes every secret of one tunnel kind. Returns "" or error.
func PhoTunClear(uuid, kind string) string {
	if err := pho.TunClear(uuid, kind); err != nil {
		return err.Error()
	}
	return ""
}

// PhoSaveAccount stores the activation credentials (phone + 6-digit code)
// in the vault. Returns "" on success, or the error message.
func PhoSaveAccount(uuid, phone, code string) string {
	if err := pho.SaveAccount(uuid, phone, code); err != nil {
		return err.Error()
	}
	return ""
}

// PhoLoadAccount returns {"phone":"...","code":"..."} (empty values if unset).
func PhoLoadAccount(uuid string) string { return pho.LoadAccount(uuid) }

// PhoClearAccount forgets the activation credentials. Returns "" or error.
func PhoClearAccount(uuid string) string {
	if err := pho.ClearAccount(uuid); err != nil {
		return err.Error()
	}
	return ""
}

func phoErrJSON(err error) string {
	msg := err.Error()
	out := make([]byte, 0, len(msg)+20)
	out = append(out, `{"error":"`...)
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		if c == '"' || c == '\\' {
			out = append(out, '\\')
		}
		if c == '\n' {
			out = append(out, '\\', 'n')
			continue
		}
		out = append(out, c)
	}
	out = append(out, '"', '}')
	return string(out)
}
