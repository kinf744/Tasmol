package config

import (
	"time"
)

type TunnelType string

const (
	TunnelSSH         TunnelType = "ssh"
	TunnelSSHSlowDNS  TunnelType = "ssh_slowdns"
	TunnelXray        TunnelType = "xray"
	TunnelXraySlowDNS TunnelType = "xray_slowdns"
	TunnelZivpn       TunnelType = "zivpn"
)

type Config struct {
	App      AppConfig      `yaml:"app" json:"app"`
	Tunnels  []TunnelConfig `yaml:"tunnels" json:"tunnels"`
	Network  NetworkConfig  `yaml:"network" json:"network"`
	Features FeaturesConfig `yaml:"features" json:"features"`
	UDPGW    UDPGWConfig    `yaml:"udpgw" json:"udpgw"`
}

type AppConfig struct {
	Name     string `yaml:"name" json:"name"`
	Version  string `yaml:"version" json:"version"`
	WebPort  int    `yaml:"web_port" json:"web_port"`
	WebHost  string `yaml:"web_host" json:"web_host"`
	LogLevel string `yaml:"log_level" json:"log_level"`
	DataDir  string `yaml:"data_dir" json:"data_dir"`
	BinDir   string `yaml:"bin_dir" json:"bin_dir"`
}

type TunnelConfig struct {
	ID        string                 `yaml:"id" json:"id"`
	Name      string                 `yaml:"name" json:"name"`
	Type      TunnelType             `yaml:"type" json:"type"`
	Enabled   bool                   `yaml:"enabled" json:"enabled"`
	Priority  int                    `yaml:"priority" json:"priority"`
	Server    ServerConfig           `yaml:"server" json:"server"`
	Auth      AuthConfig             `yaml:"auth" json:"auth"`
	Transport TransportConfig        `yaml:"transport" json:"transport"`
	Routing   RoutingConfig          `yaml:"routing" json:"routing"`
	Advanced  map[string]interface{} `yaml:"advanced" json:"advanced"`
	CreatedAt time.Time              `yaml:"created_at" json:"created_at"`
	UpdatedAt time.Time              `yaml:"updated_at" json:"updated_at"`
	LastUsed  *time.Time             `yaml:"last_used,omitempty" json:"last_used,omitempty"`
	BytesUp   int64                  `yaml:"bytes_up" json:"bytes_up"`
	BytesDown int64                  `yaml:"bytes_down" json:"bytes_down"`
}

type ServerConfig struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
	// PortRange accepts a single port ("5667") or a range ("6000-19999",
	// as used by Zivpn UDP accounts). It takes precedence over Port.
	PortRange string `yaml:"port_range,omitempty" json:"port_range,omitempty"`
	Hostname  string `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	SNI       string `yaml:"sni,omitempty" json:"sni,omitempty"`
	PublicKey string `yaml:"public_key,omitempty" json:"public_key,omitempty"`
	ShortID   string `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	// Nameserver is the dnstt/SlowDNS zone domain (e.g. ns.example.com).
	Nameserver string `yaml:"nameserver,omitempty" json:"nameserver,omitempty"`
	// DNSResolver is the UDP DNS resolver used by dnstt-client (default 8.8.8.8).
	DNSResolver string `yaml:"dns_resolver,omitempty" json:"dns_resolver,omitempty"`
}

type AuthConfig struct {
	Username     string `yaml:"username,omitempty" json:"username,omitempty"`
	Password     string `yaml:"password,omitempty" json:"password,omitempty"`
	PrivateKey   string `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	Passphrase   string `yaml:"passphrase,omitempty" json:"passphrase,omitempty"`
	UUID         string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	Flow         string `yaml:"flow,omitempty" json:"flow,omitempty"`
	Method       string `yaml:"method,omitempty" json:"method,omitempty"`
	PasswordHash string `yaml:"password_hash,omitempty" json:"password_hash,omitempty"`
}

type TransportConfig struct {
	Network     string            `yaml:"network" json:"network"`
	Headers     map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Path        string            `yaml:"path,omitempty" json:"path,omitempty"`
	Host        string            `yaml:"host,omitempty" json:"host,omitempty"`
	Seed        string            `yaml:"seed,omitempty" json:"seed,omitempty"`
	Security    string            `yaml:"security,omitempty" json:"security,omitempty"`
	Fingerprint string            `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	ALPN        []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	Obfs        string            `yaml:"obfs,omitempty" json:"obfs,omitempty"`
	ObfsParam   string            `yaml:"obfs_param,omitempty" json:"obfs_param,omitempty"`
}

type RoutingConfig struct {
	DomainStrategy string        `yaml:"domain_strategy" json:"domain_strategy"`
	Rules          []RoutingRule `yaml:"rules" json:"rules"`
	DNS            DNSConfig     `yaml:"dns" json:"dns"`
}

type RoutingRule struct {
	Type        string   `yaml:"type" json:"type"`
	Domain      []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	IP          []string `yaml:"ip,omitempty" json:"ip,omitempty"`
	Port        string   `yaml:"port,omitempty" json:"port,omitempty"`
	Network     string   `yaml:"network,omitempty" json:"network,omitempty"`
	OutboundTag string   `yaml:"outbound_tag" json:"outbound_tag"`
}

type DNSConfig struct {
	Servers  []string          `yaml:"servers" json:"servers"`
	Hosts    map[string]string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	ClientIP string            `yaml:"client_ip,omitempty" json:"client_ip,omitempty"`
	Tag      string            `yaml:"tag,omitempty" json:"tag,omitempty"`
}

type NetworkConfig struct {
	Interface  string   `yaml:"interface" json:"interface"`
	MTU        int      `yaml:"mtu" json:"mtu"`
	DNS        []string `yaml:"dns" json:"dns"`
	Gateway    string   `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	Routes     []Route  `yaml:"routes" json:"routes"`
	ExcludeIPs []string `yaml:"exclude_ips" json:"exclude_ips"`
	IncludeIPs []string `yaml:"include_ips" json:"include_ips"`
}

type Route struct {
	Network string `yaml:"network" json:"network"`
	Gateway string `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	Metric  int    `yaml:"metric,omitempty" json:"metric,omitempty"`
}

type FeaturesConfig struct {
	KillSwitch         bool     `yaml:"kill_switch" json:"kill_switch"`
	SplitTunneling     bool     `yaml:"split_tunneling" json:"split_tunneling"`
	DNSLeakProtection  bool     `yaml:"dns_leak_protection" json:"dns_leak_protection"`
	AutoReconnect      bool     `yaml:"auto_reconnect" json:"auto_reconnect"`
	ReconnectInterval  int      `yaml:"reconnect_interval" json:"reconnect_interval"`
	MaxRetries         int      `yaml:"max_retries" json:"max_retries"`
	Obfuscation        bool     `yaml:"obfuscation" json:"obfuscation"`
	ProtocolWhitelist  []string `yaml:"protocol_whitelist" json:"protocol_whitelist"`
	TrafficObfuscation string   `yaml:"traffic_obfuscation" json:"traffic_obfuscation"`
}

type UDPGWConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
	MaxClients int    `yaml:"max_clients" json:"max_clients"`
	Timeout    int    `yaml:"timeout" json:"timeout"`
	MTU        int    `yaml:"mtu" json:"mtu"`
	LogLevel   string `yaml:"log_level" json:"log_level"`
}

type ExportData struct {
	Version    string         `yaml:"version" json:"version"`
	ExportedAt time.Time      `yaml:"exported_at" json:"exported_at"`
	AppConfig  AppConfig      `yaml:"app_config" json:"app_config"`
	Tunnels    []TunnelConfig `yaml:"tunnels" json:"tunnels"`
	Network    NetworkConfig  `yaml:"network" json:"network"`
	Features   FeaturesConfig `yaml:"features" json:"features"`
	UDPGW      UDPGWConfig    `yaml:"udpgw" json:"udpgw"`
	Checksum   string         `yaml:"checksum" json:"checksum"`
}
