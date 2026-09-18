package tunnel

import (
	"encoding/json"
	"strings"
	"testing"

	"vpn-app/internal/config"
)

const fullCfg = `{
   "dns": {"servers": ["localhost"]},
   "inbounds": [{"listen": "127.0.0.1","port": "10808","protocol": "socks",
     "settings": {"auth": "noauth","udp": true},"tag": "socks-inbound"}],
   "outbounds": [
     {"mux": {"enabled": false}, "protocol": "vless",
      "proxySettings": {"tag": "alrufaaey","transportLayer": true},
      "settings": {"vnext": [{"address": "findschoolnews.blogspot.com","port": 443,
        "users": [{"encryption": "none","flow": "","id": "aaaa0000-1111-4222-8333-444455556666","level": 8}]}]},
      "streamSettings": {"network": "ws","security": "tls",
        "tlsSettings": {"serverName": "findschoolnews.blogspot.com", "allowInsecure": true},
        "wsSettings": {"headers": {"Host": "kighmu-vpn-546876213411.us-central1.run.app"},"path": "/@kighmu"}},
      "tag": "VLESS"},
     {"domainStrategy": "AsIs","protocol": "http",
      "settings": {"servers": [{"address": "157.240.9.39","port": 8080}],
        "headers": {"Host": "findschoolnews.blogspot.com:443"}},
      "tag": "alrufaaey"}
   ],
   "policy": {"levels": {"8": {"connIdle": 300,"downlinkOnly": 1,"handshake": 4,"uplinkOnly": 1}}}
}`

func TestFullXrayConfigJSON(t *testing.T) {
	cfg := &config.TunnelConfig{Advanced: map[string]interface{}{
		OutboundJSONKey: fullCfg,
	}}
	out, ok := FullXrayConfigJSON(cfg, 18777)
	if !ok {
		t.Fatal("full config not detected")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal("invalid output JSON:", err)
	}
	ins := m["inbounds"].([]interface{})
	socks := ins[0].(map[string]interface{})
	if socks["port"].(float64) != 18777 {
		t.Fatalf("socks port not normalized: %v", socks["port"])
	}
	outs := m["outbounds"].([]interface{})
	if len(outs) != 2 {
		t.Fatal("outbounds lost")
	}
	ss := outs[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
	tlsm := ss["tlsSettings"].(map[string]interface{})
	if _, bad := tlsm["allowInsecure"]; bad {
		t.Fatal("allowInsecure not removed")
	}
	if m["policy"] == nil || m["dns"] == nil {
		t.Fatal("policy/dns dropped")
	}

	// Single outbound must NOT be treated as full config.
	cfg.Advanced[OutboundJSONKey] = `{"protocol":"vless"}`
	if _, ok := FullXrayConfigJSON(cfg, 10808); ok {
		t.Fatal("single outbound wrongly detected as full config")
	}
}

func TestGenerateConfigFull(t *testing.T) {
	c := config.TunnelConfig{Advanced: map[string]interface{}{OutboundJSONKey: fullCfg}}
	xt := NewXrayTunnel(&c)
	xt.socksPort = 15555
	s, err := xt.generateConfig()
	if err != nil || !strings.Contains(s, "15555") {
		t.Fatalf("generateConfig: %v", err)
	}
}
