package tunnel

import (
	"context"
	"fmt"
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

func CreateTunnel(cfg *config.TunnelConfig) (Tunnel, error) {
	switch cfg.Type {
	case config.TunnelSSH:
		return NewSSHTunnel(cfg), nil
	case config.TunnelSSHSlowDNS:
		return NewSSHSlowDNSTunnel(cfg), nil
	case config.TunnelXray:
		return NewXrayTunnel(cfg), nil
	case config.TunnelXraySlowDNS:
		return NewXraySlowDNSTunnel(cfg), nil
	case config.TunnelZivpn:
		return NewZivpnTunnel(cfg), nil
	default:
		return nil, fmt.Errorf("unknown tunnel type: %s", cfg.Type)
	}
}
