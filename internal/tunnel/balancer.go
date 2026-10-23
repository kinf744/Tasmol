package tunnel

import (
	"encoding/json"
	"fmt"

	"vpn-app/internal/config"
)

const DefaultFrontPort = 10900

const RoundRobinOutboundTag = "rr"

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

		for _, eo := range extraOutbounds(tc) {
			if m, ok := eo.(map[string]interface{}); ok && m != nil {
				if t, _ := m["tag"].(string); t == "" {
					m["tag"] = fmt.Sprintf("lb-%d-eb", i)
				}
				outbounds = append(outbounds, m)
			} else {
				outbounds = append(outbounds, eo)
			}
		}
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
		"dns": map[string]interface{}{
			"servers": XrayDNSServers(),
		},
		"routing": map[string]interface{}{

			"domainStrategy": "UseIP",
			"rules": []interface{}{
				map[string]interface{}{
					"type": "field", "network": "tcp,udp", "balancerTag": RoundRobinOutboundTag,
				},
			},

			"balancers": []interface{}{
				map[string]interface{}{
					"tag":      RoundRobinOutboundTag,
					"selector": []string{"lb-"},
					"strategy": map[string]interface{}{"type": "roundRobin"},
				},
			},
		},
	}

	return json.Marshal(doc)
}

func balancerOutbound(tc *config.TunnelConfig, tag string) (map[string]interface{}, error) {
	var ob map[string]interface{}
	switch tc.Type {
	case config.TunnelSSH, config.TunnelSSHSlowDNS, config.TunnelZivpn, config.TunnelHysteria:
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
		fwd := DnsttForwardPortLive(tc, DefaultXraySlowDNSFwdPort)
		ob = SlowDNSOutbound(tc, fwd)
	default:
		return nil, fmt.Errorf("unsupported tunnel type: %s", tc.Type)
	}
	ob["tag"] = tag
	return ob, nil
}
