// Package pholib exposes the hardened control-plane (activation API,
// encrypted storage, runtime self-check) to Android via gomobile.
// Java face: pholib.Pholib.<fn>.
package pholib

import (
	"vpn-app/internal/pho"
)

// Init initializes the vault store. Call once on app start with the
// app-private files dir.
func Init(filesDir string) string {
	if err := pho.Init(filesDir); err != nil {
		return err.Error()
	}
	return ""
}

// DeviceSelfCheck returns JSON {"traced":bool,"emulator":bool}.
func DeviceSelfCheck() string { return pho.SelfCheck() }

// ApiActivate registers a device. Returns API JSON, or {"error":...}.
func ApiActivate(phone, code, uuid string) string {
	s, err := pho.Activate(phone, code, uuid)
	if err != nil {
		return errJSON(err)
	}
	return s
}

// ApiFetchConfigs returns the configs JSON, or {"error":...}.
func ApiFetchConfigs(uuid, code string) string {
	s, err := pho.FetchConfigs(uuid, code)
	if err != nil {
		return errJSON(err)
	}
	return s
}

// ApiCheck returns the device-check JSON, or {"error":...}.
func ApiCheck(uuid string) string {
	s, err := pho.Check(uuid)
	if err != nil {
		return errJSON(err)
	}
	return s
}

// -- encrypted vault (credentials/configs never stored in plaintext) ----

func VaultPut(uuid, key, value string) string {
	if err := pho.VaultPut(uuid, key, value); err != nil {
		return err.Error()
	}
	return ""
}

func VaultGet(uuid, key string) string { return pho.VaultGet(uuid, key) }

func VaultClear(uuid string) { pho.VaultClear(uuid) }

// ApiResetPin forgets the TLS pin (only for deliberate cert rotation).
func ApiResetPin() { pho.ResetPin() }

func errJSON(err error) string { return `{"error":` + `"` + escape(err.Error()) + `"}` }

func escape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '"', '\\':
			out = append(out, '\\', r)
		case '\n':
			out = append(out, '\\', 'n')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}
