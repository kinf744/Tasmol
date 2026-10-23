package vpnlib

import (
	"vpn-app/internal/pho"
)

func PhoInit(filesDir string) string {
	if err := pho.Init(filesDir); err != nil {
		return err.Error()
	}
	return ""
}

func PhoSelfCheck() string { return pho.SelfCheck() }

func PhoActivate(phone, code, uuid, proof string) string {
	s, err := pho.Activate(phone, code, uuid, proof)
	if err != nil {
		return phoErrJSON(err)
	}
	return s
}

func PhoFetchConfigs(uuid, code string) string {
	s, err := pho.FetchConfigs(uuid, code)
	if err != nil {
		return phoErrJSON(err)
	}
	return s
}

func PhoCheck(uuid, proof string) string {
	s, err := pho.Check(uuid, proof)
	if err != nil {
		return phoErrJSON(err)
	}
	return s
}

func PhoVaultPut(uuid, key, value string) string {
	if err := pho.VaultPut(uuid, key, value); err != nil {
		return err.Error()
	}
	return ""
}

func PhoVaultGet(uuid, key string) string { return pho.VaultGet(uuid, key) }

func PhoVaultClear(uuid string) { pho.VaultClear(uuid) }

func PhoResetPin() { pho.ResetPin() }

func PhoDeviceProof(uuid, androidId string) string { return pho.DeviceProof(uuid, androidId) }

func PhoIdentityEnsure() string { return pho.IdentityEnsure() }

func PhoIdentityUuid(androidId string) string { return pho.IdentityUuid(androidId) }

func PhoPortRelay() int { return pho.PortRelay() }

func PhoPortUdpgw() int { return pho.PortUdpgw() }

func PhoPortManage() int { return pho.PortManage() }

func PhoLogFileName() string { return pho.LogFileName() }

func PhoSetProxy(addr string) { pho.SetProxy(addr) }

func PhoTunPut(uuid, kind, field, value string) string {
	if err := pho.TunPut(uuid, kind, field, value); err != nil {
		return err.Error()
	}
	return ""
}

func PhoTunGet(uuid, kind, field string) string { return pho.TunGet(uuid, kind, field) }

func PhoTunClear(uuid, kind string) string {
	if err := pho.TunClear(uuid, kind); err != nil {
		return err.Error()
	}
	return ""
}

func PhoSaveAccount(uuid, phone, code string) string {
	if err := pho.SaveAccount(uuid, phone, code); err != nil {
		return err.Error()
	}
	return ""
}

func PhoLoadAccount(uuid string) string { return pho.LoadAccount(uuid) }

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
