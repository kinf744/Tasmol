package tunnel

import (
	"fmt"
	"net"
	"os"
	"strings"

	"vpn-app/internal/config"
)

func sshModeName(cfg *config.TunnelConfig) string {
	if cfg == nil {
		return "?"
	}
	mode := strings.TrimSpace(advStr(cfg.Advanced, "ssh_mode", ""))
	if mode == "" {

		var parts []string
		if sshTLSRequested(cfg) {
			parts = append(parts, "tls")
		}
		if strings.TrimSpace(cfg.SSH.Proxy) != "" {
			parts = append(parts, "proxy")
		}
		if strings.TrimSpace(cfg.SSH.Payload) != "" {
			parts = append(parts, "payload")
		}
		if len(parts) == 0 {
			return "SSH-Direct"
		}
		return "SSH-" + strings.Join(parts, "-")
	}
	switch mode {
	case "direct":
		return "SSH-Direct"
	case "proxy":
		return "SSH-Proxy"
	case "payload":
		return "SSH-Payload"
	case "proxy_payload":
		return "SSH-Proxy-Payload"
	case "tls":
		return "SSH-TLS"
	case "tls_proxy":
		return "SSH-TLS-Proxy"
	case "tls_payload":
		return "SSH-TLS-Payload"
	case "tls_proxy_payload":
		return "SSH-TLS-Proxy-Payload"
	case "dnstt":
		return "SSH-DNSTT"
	}
	return "SSH-" + mode
}

func boolTag(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func logSSHProfile(cfg *config.TunnelConfig, engine string, socksPort int) {
	if cfg == nil {
		return
	}
	journal := func(format string, args ...interface{}) {
		Connf("ssh", format, args...)
	}

	journal("profile %q (id=%s)", cfg.Name, cfg.ID)
	journal("  type=%s protocol=%s engine=%s", cfg.Type, sshModeName(cfg), engine)
	journal("  target=%s:%d", cfg.Server.Host, cfg.Server.Port)
	journal("  user=%s auth: password=%s private_key=%s passphrase=%s",
		hideUser(cfg, cfg.Auth.Username),
		boolTag(cfg.Auth.Password != ""),
		boolTag(strings.TrimSpace(cfg.Auth.PrivateKey) != ""),
		boolTag(cfg.Auth.Passphrase != ""))

	if p := strings.TrimSpace(cfg.SSH.Proxy); p != "" {
		journal("  proxy=%s auth=%s payload=%d bytes",
			p, boolTag(advStr(cfg.Advanced, "proxy_user", "") != ""),
			len(strings.TrimSpace(cfg.SSH.Payload)))
	}
	if pl := strings.TrimSpace(cfg.SSH.Payload); pl != "" {
		journal("  payload: %s", summarizePayload(pl))
	}
	if sshTLSRequested(cfg) {
		journal("  tls: sni=%q version=%s (verification skipped: tunnel certs are self-signed)",
			cfg.Server.SNI, advStr(cfg.Advanced, "ssh_tls_version", "default"))
	}
	if cfg.Type == config.TunnelSSHSlowDNS {
		mode := "udp"
		if v, ok := cfg.Advanced["dnstt_tcp"]; ok {
			if b, ok := v.(bool); ok && b {
				mode = "tcp"
			}
		} else if DnsttUseTCP {
			mode = "tcp (global boost)"
		}
		journal("  dnstt: ns=%q resolver=%s transport=%s key=%d chars",
			DnsttDomain(cfg), DnsttResolver(cfg), mode,
			len(strings.TrimSpace(DnsttPubKey(cfg))))
	}
	if socksPort > 0 {
		journal("  socks=127.0.0.1:%d", socksPort)
	}
	if cfg.Type == config.TunnelSSH || cfg.Type == config.TunnelSSHSlowDNS {
		journal("  udpgw: port=%s transparent_dns=%s",
			advStr(cfg.Advanced, "udpgw_port", "(global)"),
			boolTag(advBool(cfg.Advanced, "udpgw_dns", true)))
	}
}

func summarizePayload(payload string) string {
	one := strings.ReplaceAll(strings.ReplaceAll(payload, "\r\n", " | "), "\n", " | ")
	one = strings.TrimSpace(one)
	if len(one) > 200 {
		one = one[:200] + "…"
	}
	return one
}

func sshStep(format string, args ...interface{}) {
	Infof("ssh", format, args...)
}

func sshDiagError(stage string, err error, hint string) {
	if err == nil {
		return
	}
	msg := strings.TrimSpace(err.Error())
	var extra string
	switch {
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "context deadline exceeded"):
		extra = " -> timeout: reseau filtre/lent, ou port bloque"
	case strings.Contains(msg, "connection refused"):
		extra = " -> port ferme / service non demarre"
	case strings.Contains(msg, "no such host"):
		extra = " -> DNS: nom de domaine non resolvable sur ce reseau"
	case strings.Contains(msg, "certificate"), strings.Contains(msg, "tls:"):
		extra = " -> TLS: certificat refuse (SNI incorrect ?) ou TLS non supporte par la cible"
	case strings.Contains(msg, "407"):
		extra = " -> proxy: 407, identifiants proxy a verifier"
	case strings.Contains(msg, "403"), strings.Contains(msg, "404"), strings.Contains(msg, "400"):
		extra = " -> proxy: requete rejetee (payload/host entete a corriger)"
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods"):
		extra = " -> auth SSH: mot de passe / cle / utilisateur refuses par le serveur"
	}
	Errorf("ssh", "%s failed: %v%s", stage, err, extra)
	if hint != "" {
		Infof("ssh", "  hint: %s", hint)
	}
}

func logSSHStop(cfg *config.TunnelConfig, err error) {
	name := ""
	if cfg != nil {
		name = cfg.Name
	}
	if err != nil {
		Infof("ssh", "tunnel %q stopped: %v", name, err)
		return
	}
	Infof("ssh", "tunnel %q stopped (requested)", name)
}

func sshDialHints(cfg *config.TunnelConfig, err error) string {
	if err == nil || cfg == nil {
		return ""
	}
	msg := err.Error()
	var hints []string
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline") {
		hints = append(hints, "verifiez le port, le pare-feu et le blocage operateur")
	}
	if strings.Contains(msg, "no such host") {
		hints = append(hints, "le resolvateur du systeme ne repond pas: essayez une IP brute")
	}
	if sshTLSRequested(cfg) && strings.Contains(msg, "tls") {
		hints = append(hints, "verifiez le SNI et que la cible parle bien TLS")
	}
	if strings.TrimSpace(cfg.SSH.Proxy) != "" {
		hints = append(hints, "verifiez le proxy et son port (CONNECT doit repondre 200)")
	}
	if strings.TrimSpace(cfg.SSH.Payload) != "" {
		hints = append(hints, "verifiez le payload (jetons [crlf] [host])")
	}
	return strings.Join(hints, " ; ")
}

func sshResolveEndpoint(host string) string {
	h := strings.TrimSpace(host)
	if h == "" || net.ParseIP(h) != nil {
		return h
	}
	infos, err := net.LookupIP(h)
	if err != nil {
		Warnf("ssh", "resolve %s failed: %v", h, err)
		return h
	}
	var ips []string
	for _, ip := range infos {
		ips = append(ips, ip.String())
	}
	Infof("ssh", "resolve %s -> %s", h, strings.Join(ips, ","))
	return h
}

func sshExitHint(code int) string {
	switch {
	case code == 255:
		return "255 = erreur de connexion ou d'authentification SSH (utilisateur / mot de passe / cle)"
	case code == 0:
		return ""
	default:
		return fmt.Sprintf("code de sortie openssh %d", code)
	}
}

func sshBinaryInfo(bin string, err error) {
	if err != nil {
		sshDiagError("ssh binary", err, "verifiez que le binaire openssh est installe")
		return
	}
	Infof("ssh", "binary=%s", bin)
	if st, err := os.Stat(bin); err == nil {
		Infof("ssh", "binary size=%d mode=%s", st.Size(), st.Mode())
	} else {
		Warnf("ssh", "binary stat failed: %v", err)
	}
}
