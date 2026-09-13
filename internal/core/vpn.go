package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vpn-app/internal/config"
	"vpn-app/internal/features"
	"vpn-app/internal/tunnel"
)

type VPNCore struct {
	mu             sync.RWMutex
	config         *config.Config
	configManager  *config.Manager
	tunnelManager  tunnel.Manager
	featureManager *features.FeatureManager
	running        bool
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// Options tunes VPNCore behaviour per platform.
type Options struct {
	// EnableFeatures turns on netlink-based professional features
	// (kill switch, split tunneling, DNS leak protection). They require
	// root; keep enabled on servers/Termux, disabled in mobile (Android
	// VpnService) mode where traffic capture replaces them.
	EnableFeatures bool
}

func NewVPNCore(configManager *config.Manager) (*VPNCore, error) {
	return NewVPNCoreWithOptions(configManager, Options{EnableFeatures: true})
}

func NewVPNCoreWithOptions(configManager *config.Manager, opts Options) (*VPNCore, error) {
	cfg := configManager.Get()

	// Point tunnel engines at the repository-bundled official binaries.
	tunnel.BinDir = cfg.App.BinDir

	tunnelManager := tunnel.NewManager(cfg.UDPGW)

	for _, tunnelCfg := range cfg.Tunnels {
		t, err := tunnel.CreateTunnel(&tunnelCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create tunnel %s: %w", tunnelCfg.ID, err)
		}
		if err := tunnelManager.Add(t); err != nil {
			return nil, err
		}
	}

	var featureManager *features.FeatureManager
	if opts.EnableFeatures {
		featureManager = features.NewFeatureManager(
			&cfg.Features,
			cfg.Network.Interface,
			cfg.Network.Gateway,
			cfg.Network.DNS,
		)
	}

	v := &VPNCore{
		configManager:  configManager,
		config:         cfg,
		tunnelManager:  tunnelManager,
		featureManager: featureManager,
	}

	configManager.OnChange(v.onConfigChange)

	return v, nil
}

func (v *VPNCore) onConfigChange(cfg *config.Config) {
	v.mu.Lock()
	v.config = cfg
	fm := v.featureManager
	v.mu.Unlock()

	if fm != nil {
		fm.UpdateConfig(&cfg.Features)
	}
}

func (v *VPNCore) Start(ctx context.Context) error {
	v.mu.Lock()
	if v.running {
		v.mu.Unlock()
		return nil
	}
	v.ctx, v.cancel = context.WithCancel(ctx)
	v.running = true
	v.mu.Unlock()

	if v.featureManager != nil {
		if err := v.featureManager.Start(v.ctx); err != nil {
			return fmt.Errorf("failed to start features: %w", err)
		}
	}

	if err := v.tunnelManager.StartAll(v.ctx); err != nil {
		if v.featureManager != nil {
			v.featureManager.Stop(v.ctx)
		}
		return fmt.Errorf("failed to start tunnels: %w", err)
	}

	v.wg.Add(1)
	go v.statsCollector()

	return nil
}

func (v *VPNCore) Stop(ctx context.Context) error {
	v.mu.Lock()
	if !v.running {
		v.mu.Unlock()
		return nil
	}
	v.running = false
	if v.cancel != nil {
		v.cancel()
	}
	v.mu.Unlock()

	if err := v.tunnelManager.StopAll(v.ctx); err != nil {
		return fmt.Errorf("failed to stop tunnels: %w", err)
	}

	if v.featureManager != nil {
		if err := v.featureManager.Stop(v.ctx); err != nil {
			return fmt.Errorf("failed to stop features: %w", err)
		}
	}

	v.wg.Wait()
	return nil
}

func (v *VPNCore) IsRunning() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.running
}

func (v *VPNCore) GetTunnelManager() tunnel.Manager {
	return v.tunnelManager
}

func (v *VPNCore) GetFeatureManager() *features.FeatureManager {
	return v.featureManager
}

// FeatureStatus reports professional-feature states. It returns an empty
// map when features are disabled (mobile mode) instead of nil-dereferencing.
func (v *VPNCore) FeatureStatus() map[string]bool {
	v.mu.RLock()
	fm := v.featureManager
	v.mu.RUnlock()
	if fm == nil {
		return map[string]bool{}
	}
	return fm.GetStatus()
}

func (v *VPNCore) GetConfig() *config.Config {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.config
}

func (v *VPNCore) GetConfigManager() *config.Manager {
	return v.configManager
}

func (v *VPNCore) statsCollector() {
	defer v.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			v.collectStats()
		}
	}
}

func (v *VPNCore) collectStats() {
	tunnels := v.tunnelManager.List()
	for _, t := range tunnels {
		_ = t.Stats()
		// Stats are exposed via the API; persistence happens on tunnel update
	}
}
