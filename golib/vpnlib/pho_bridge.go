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
func PhoActivate(phone, code, uuid string) string {
	s, err := pho.Activate(phone, code, uuid)
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
func PhoCheck(uuid string) string {
	s, err := pho.Check(uuid)
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
