package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

type Manager struct {
	config    *Config
	path      string
	watcher   *fsnotify.Watcher
	callbacks []func(*Config)
}

func NewManager(configPath string) (*Manager, error) {
	m := &Manager{
		path:      configPath,
		callbacks: make([]func(*Config), 0),
	}

	if err := m.load(); err != nil {
		return nil, err
	}

	if err := m.watch(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) load() error {
	// Direct YAML decode (no viper): every struct field maps 1:1 via
	// yaml tags, so slowdns keys and port ranges can never be dropped
	// by a mapping layer on load.
	raw, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			m.config = m.defaultConfig()
			return m.Save()
		}
		return err
	}

	m.config = &Config{}
	if err := yaml.Unmarshal(raw, m.config); err != nil {
		return err
	}

	m.setDefaults()
	return nil
}

func (m *Manager) defaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".vpn-app")
	binDir := "/data/data/com.termux/files/usr/bin"

	return &Config{
		App: AppConfig{
			Name:     "VPN App",
			Version:  "1.0.0",
			WebPort:  8080,
			WebHost:  "0.0.0.0",
			LogLevel: "info",
			DataDir:  dataDir,
			BinDir:   binDir,
		},
		Tunnels: []TunnelConfig{},
		Network: NetworkConfig{
			Interface:  "tun0",
			MTU:        1500,
			DNS:        []string{"1.1.1.1", "8.8.8.8"},
			ExcludeIPs: []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
		Features: FeaturesConfig{
			KillSwitch:        true,
			SplitTunneling:    false,
			DNSLeakProtection: true,
			AutoReconnect:     true,
			ReconnectInterval: 5,
			MaxRetries:        3,
			Obfuscation:       false,
		},
		UDPGW: UDPGWConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:7300",
			MaxClients: 100,
			Timeout:    30,
			MTU:        1500,
			LogLevel:   "info",
		},
	}
}

func (m *Manager) setDefaults() {
	if m.config.App.WebPort == 0 {
		m.config.App.WebPort = 8080
	}
	if m.config.App.WebHost == "" {
		m.config.App.WebHost = "0.0.0.0"
	}
	if m.config.Network.MTU == 0 {
		m.config.Network.MTU = 1500
	}
	if m.config.UDPGW.ListenAddr == "" {
		m.config.UDPGW.ListenAddr = "127.0.0.1:7300"
	}
	if m.config.UDPGW.MaxClients == 0 {
		m.config.UDPGW.MaxClients = 100
	}
}

func (m *Manager) watch() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = w

	go func() {
		for {
			select {
			case event, ok := <-w.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					m.load()
					m.notifyCallbacks()
				}
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()

	dir := filepath.Dir(m.path)
	return w.Add(dir)
}

func (m *Manager) OnChange(callback func(*Config)) {
	m.callbacks = append(m.callbacks, callback)
}

func (m *Manager) notifyCallbacks() {
	for _, cb := range m.callbacks {
		cb(m.config)
	}
}

func (m *Manager) Get() *Config {
	return m.config
}

func (m *Manager) GetTunnel(id string) *TunnelConfig {
	for i := range m.config.Tunnels {
		if m.config.Tunnels[i].ID == id {
			return &m.config.Tunnels[i]
		}
	}
	return nil
}

func (m *Manager) AddTunnel(tunnel *TunnelConfig) error {
	tunnel.ID = generateID()
	tunnel.CreatedAt = time.Now()
	tunnel.UpdatedAt = time.Now()

	if tunnel.Type == TunnelZivpn {
		// Defaults: full client range split into 8 sub-ranges (one
		// uz_core per sub-range, round-robin balanced for throughput).
		if tunnel.Server.PortRange == "" && tunnel.Server.Port == 0 {
			tunnel.Server.PortRange = "6000-7750,7751-9500,9501-11250,11251-13000," +
				"13001-14750,14751-16500,16501-18250,18251-19999"
		}
		if tunnel.Transport.Network == "" {
			tunnel.Transport.Network = "udp"
		}
		if tunnel.Transport.Obfs == "" {
			tunnel.Transport.Obfs = "salamander"
		}
		if tunnel.Transport.ObfsParam == "" {
			// Fixed obfs value used by the Zivpn UDP tunnel
			// (see tunnel.DefaultZivpnObfsPassword).
			tunnel.Transport.ObfsParam = "hu``hqb`c"
		}
	}

	m.config.Tunnels = append(m.config.Tunnels, *tunnel)
	return m.Save()
}

func (m *Manager) UpdateTunnel(id string, tunnel TunnelConfig) error {
	for i := range m.config.Tunnels {
		if m.config.Tunnels[i].ID == id {
			tunnel.ID = id
			tunnel.CreatedAt = m.config.Tunnels[i].CreatedAt
			tunnel.UpdatedAt = time.Now()
			tunnel.BytesUp = m.config.Tunnels[i].BytesUp
			tunnel.BytesDown = m.config.Tunnels[i].BytesDown
			m.config.Tunnels[i] = tunnel
			return m.Save()
		}
	}
	return fmt.Errorf("tunnel not found: %s", id)
}

func (m *Manager) DeleteTunnel(id string) error {
	for i := range m.config.Tunnels {
		if m.config.Tunnels[i].ID == id {
			m.config.Tunnels = append(m.config.Tunnels[:i], m.config.Tunnels[i+1:]...)
			return m.Save()
		}
	}
	return fmt.Errorf("tunnel not found: %s", id)
}

func (m *Manager) Save() error {
	data, err := yaml.Marshal(m.config)
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0644)
}

func (m *Manager) Export() (*ExportData, error) {
	checksum := m.calculateChecksum()
	return &ExportData{
		Version:    m.config.App.Version,
		ExportedAt: time.Now(),
		AppConfig:  m.config.App,
		Tunnels:    m.config.Tunnels,
		Network:    m.config.Network,
		Features:   m.config.Features,
		UDPGW:      m.config.UDPGW,
		Checksum:   checksum,
	}, nil
}

func (m *Manager) ExportToFile(path string) error {
	data, err := m.Export()
	if err != nil {
		return err
	}
	content, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0644)
}

func (m *Manager) ImportFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var data ExportData
	if err := yaml.Unmarshal(content, &data); err != nil {
		return err
	}

	if err := m.verifyChecksum(&data); err != nil {
		return err
	}

	m.config.App = data.AppConfig
	m.config.Tunnels = data.Tunnels
	m.config.Network = data.Network
	m.config.Features = data.Features
	m.config.UDPGW = data.UDPGW

	return m.Save()
}

func (m *Manager) ImportJSON(content []byte) error {
	var data ExportData
	if err := json.Unmarshal(content, &data); err != nil {
		return err
	}
	return m.importData(&data)
}

func (m *Manager) ImportYAML(content []byte) error {
	var data ExportData
	if err := yaml.Unmarshal(content, &data); err != nil {
		return err
	}
	return m.importData(&data)
}

func (m *Manager) importData(data *ExportData) error {
	if err := m.verifyChecksum(data); err != nil {
		return err
	}

	m.config.App = data.AppConfig
	m.config.Tunnels = data.Tunnels
	m.config.Network = data.Network
	m.config.Features = data.Features
	m.config.UDPGW = data.UDPGW

	return m.Save()
}

func (m *Manager) calculateChecksum() string {
	data := fmt.Sprintf("%v%v%v%v%v", m.config.App, m.config.Tunnels, m.config.Network, m.config.Features, m.config.UDPGW)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (m *Manager) verifyChecksum(data *ExportData) error {
	expected := data.Checksum
	data.Checksum = ""
	actual := m.calculateChecksumFromData(data)
	if expected != actual {
		return fmt.Errorf("checksum mismatch: data may be corrupted")
	}
	return nil
}

func (m *Manager) calculateChecksumFromData(data *ExportData) string {
	content := fmt.Sprintf("%v%v%v%v%v", data.AppConfig, data.Tunnels, data.Network, data.Features, data.UDPGW)
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func (m *Manager) Close() error {
	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
