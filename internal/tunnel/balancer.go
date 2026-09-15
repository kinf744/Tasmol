package tunnel

import (
	"encoding/json"
	"fmt"

	"vpn-app/internal/config"
)

// DefaultFrontPort is the local SOCKS5 endpoint of the round-robin front
// (an Xray process built by BuildBalancerFront). It sits outside the
// per-tunnel SOCKS range (10801-10810).
const DefaultFrontPort = 10900

// RoundRobinOutboundTag is the balancer tag used in the front config.
const RoundRobinOutboundTag = "rr"

// BuildBalancerFront builds a front Xray config routing all TCP+UDP through
// Xray's built-in round-robin balancer ("strategy": "roundrobin") over one
// outbound per profile. xray-native profiles get VLESS outbounds, every
// other type gets a SOCKS outbound toward its already-running local helper
// (native SSH, dnstt+SSH, dnstt+Xray forward, uz_core balancer).
//
// profiles must contain at least 2 configs; single-profile sessions must
// NOT use a balancer (direct upstream instead).
func BuildBalancerFront(profiles []*config.TunnelConfig, socksPort int) ([]byte, error) {
	if len(profiles) < 2 {
		return nil, fmt.Errorf("round-robin needs at least 2 profiles, got %d", len(profiles))
	}

	outbounds := make([]interface{}, 0, len(profiles)+1)
	for i, tc := range profiles {
		tag := fmt.Sprintf("lb-%d", i)
		ob, err := balancerOutbound(tc, tag)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", tc.Name, err)
		}
		outbounds = append(outbounds, ob)
	}

	doc := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "rr-in",
				"protocol": "socks",
				"listen":   "127.0.0.1",
				"port":     socksPort,
				"settings": map[string]interface{}{
					"udp":  true,
					"auth": "noauth",
				},
			},
		},
		"outbounds": outbounds,
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []interface{}{
				map[string]interface{}{
					"type": "field", "network": "tcp,udp", "balancerTag": RoundRobinOutboundTag,
				},
			},
			// NOTE: balancers MUST live inside "routing" (not top-level),
			// otherwise Xray fails with "balancer rr not found".
			"balancers": []interface{}{
				map[string]interface{}{
					"tag":      RoundRobinOutboundTag,
					"selector": []string{"lb-"},
					"strategy": "roundrobin",
				},
			},
		},
	}

	return json.Marshal(doc)
}

// balancerOutbound builds the lb-N outbound for one profile: native VLESS
// for xray profiles (direct or via the dnstt forward), SOCKS toward the
// local helper for ssh / ssh_slowdns / zivpn.
func balancerOutbound(tc *config.TunnelConfig, tag string) (map[string]interface{}, error) {
	var ob map[string]interface{}
	switch tc.Type {
	case config.TunnelSSH, config.TunnelSSHSlowDNS, config.TunnelZivpn:
		ob = map[string]interface{}{
			"protocol": "socks",
			"settings": map[string]interface{}{
				"servers": []map[string]interface{}{
					{"address": "127.0.0.1", "port": SocksPortLive(tc)},
				},
			},
		}
	case config.TunnelXray:
		if !HasOutboundJSON(tc) && tc.Auth.UUID == "" {
			return nil, fmt.Errorf("xray uuid is required (auth.uuid) or paste a link/JSON")
		}
		port := tc.Server.Port
		if port == 0 {
			port = 443
		}
		ob = TunnelOutbound(tc, tc.Server.Host, port)
	case config.TunnelXraySlowDNS:
		if !HasOutboundJSON(tc) && tc.Auth.UUID == "" {
			return nil, fmt.Errorf("xray uuid is required (auth.uuid) or paste a link/JSON")
		}
		fwd := DnsttForwardPort(tc, DefaultXraySlowDNSFwdPort)
		ob = SlowDNSOutbound(tc, fwd)
	default:
		return nil, fmt.Errorf("unsupported tunnel type: %s", tc.Type)
	}
	ob["tag"] = tag
	return ob, nil
}
