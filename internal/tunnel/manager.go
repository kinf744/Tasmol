package tunnel

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"vpn-app/internal/config"
)

type manager struct {
	mu       sync.RWMutex
	tunnels  map[string]Tunnel
	statusCb func(Tunnel, Status)
	statsCb  func(Tunnel, Stats)
	udpgw    UDPGW
}

func NewManager(udpgwConfig config.UDPGWConfig) Manager {
	return &manager{
		tunnels: make(map[string]Tunnel),
		udpgw:   NewUDPGWProxy(udpgwConfig),
	}
}

func (m *manager) Add(tunnel Tunnel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tunnels[tunnel.ID()]; exists {
		return fmt.Errorf("tunnel with ID %s already exists", tunnel.ID())
	}

	m.tunnels[tunnel.ID()] = tunnel
	return nil
}

func (m *manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tunnel, exists := m.tunnels[id]
	if !exists {
		return fmt.Errorf("tunnel not found: %s", id)
	}

	ctx := context.Background()
	if err := tunnel.Stop(ctx); err != nil {
		return err
	}

	delete(m.tunnels, id)
	return nil
}

func (m *manager) Get(id string) (Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tunnel, ok := m.tunnels[id]
	return tunnel, ok
}

func (m *manager) List() []Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		result = append(result, t)
	}
	return result
}

func (m *manager) GetRunning() []Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Tunnel, 0)
	for _, t := range m.tunnels {
		if t.Status() == StatusRunning {
			result = append(result, t)
		}
	}
	return result
}

func (m *manager) StartAll(ctx context.Context) error {
	m.mu.RLock()
	tunnels := make([]Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		if t.Config().Enabled {
			tunnels = append(tunnels, t)
		}
	}
	m.mu.RUnlock()

	for _, t := range tunnels {
		if err := t.Start(ctx); err != nil {
			return fmt.Errorf("failed to start tunnel %s: %w", t.ID(), err)
		}
	}

	if m.udpgw != nil {
		return m.udpgw.Start(ctx)
	}

	return nil
}

func (m *manager) StopAll(ctx context.Context) error {
	m.mu.RLock()
	tunnels := make([]Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		tunnels = append(tunnels, t)
	}
	m.mu.RUnlock()

	for _, t := range tunnels {
		if err := t.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop tunnel %s: %w", t.ID(), err)
		}
	}

	if m.udpgw != nil {
		return m.udpgw.Stop(ctx)
	}

	return nil
}

func (m *manager) OnStatusChange(cb func(Tunnel, Status)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusCb = cb
}

func (m *manager) OnStatsUpdate(cb func(Tunnel, Stats)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statsCb = cb
}

func (m *manager) GetUDPGW() UDPGW {
	return m.udpgw
}

// useNativeSSH reports whether the pure-Go SSH implementation applies:
// global mobile default, overridable per tunnel via Advanced["native_ssh"].
func useNativeSSH(cfg *config.TunnelConfig) bool {
	if cfg.Advanced != nil {
		if v, ok := cfg.Advanced["native_ssh"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return NativeSSH
}

func CreateTunnel(cfg *config.TunnelConfig) (Tunnel, error) {
	engine := ""
	switch cfg.Type {
	case config.TunnelSSH:
		if useNativeSSH(cfg) {
			engine = "native-ssh"
			Tracef("[tunnel] %q (id=%s type=ssh) engine=%s", cfg.Name, cfg.ID, engine)
			return NewNativeSSHTunnel(cfg), nil
		}
		if strings.TrimSpace(cfg.SSH.Proxy) != "" || strings.TrimSpace(cfg.SSH.Payload) != "" {
			return nil, fmt.Errorf("ssh proxy/payload need the native SSH engine (advanced.native_ssh=true)")
		}
		engine = "openssh-process"
		Tracef("[tunnel] %q (id=%s type=ssh) engine=%s", cfg.Name, cfg.ID, engine)
		return NewSSHTunnel(cfg), nil
	case config.TunnelSSHSlowDNS:
		if useNativeSSH(cfg) {
			engine = "native-ssh+dnstt"
			Tracef("[tunnel] %q (id=%s type=ssh_slowdns) engine=%s", cfg.Name, cfg.ID, engine)
			return NewNativeSSHSlowDNSTunnel(cfg), nil
		}
		engine = "openssh-process+dnstt"
		Tracef("[tunnel] %q (id=%s type=ssh_slowdns) engine=%s", cfg.Name, cfg.ID, engine)
		return NewSSHSlowDNSTunnel(cfg), nil
	case config.TunnelXray:
		Tracef("[tunnel] %q (id=%s type=xray) engine=xray-process", cfg.Name, cfg.ID)
		return NewXrayTunnel(cfg), nil
	case config.TunnelXraySlowDNS:
		Tracef("[tunnel] %q (id=%s type=xray_slowdns) engine=xray-process+dnstt", cfg.Name, cfg.ID)
		return NewXraySlowDNSTunnel(cfg), nil
	case config.TunnelZivpn:
		Tracef("[tunnel] %q (id=%s type=zivpn) engine=uz_core", cfg.Name, cfg.ID)
		return NewZivpnTunnel(cfg), nil
	default:
		return nil, fmt.Errorf("unknown tunnel type: %s", cfg.Type)
	}
}
