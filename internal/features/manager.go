package features

import (
	"context"
	"fmt"
	"sync"

	"vpn-app/internal/config"
)

type FeatureManager struct {
	mu            sync.RWMutex
	config        *config.FeaturesConfig
	killSwitch    *KillSwitch
	splitTunnel   *SplitTunnel
	dnsLeak       *DNSLeakProtection
	interfaceName string
	vpnGateway    string
	dnsServers    []string
	running       bool
	stopChan      chan struct{}
}

func NewFeatureManager(cfg *config.FeaturesConfig, interfaceName, vpnGateway string, dnsServers []string) *FeatureManager {
	return &FeatureManager{
		config:        cfg,
		interfaceName: interfaceName,
		vpnGateway:    vpnGateway,
		dnsServers:    dnsServers,
		killSwitch:    NewKillSwitch(interfaceName, vpnGateway),
		splitTunnel:   NewSplitTunnel(interfaceName, vpnGateway),
		dnsLeak:       NewDNSLeakProtection(interfaceName, vpnGateway, dnsServers),
		stopChan:      make(chan struct{}),
	}
}

func (fm *FeatureManager) Start(ctx context.Context) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.running {
		return nil
	}

	if fm.config.KillSwitch {
		if err := fm.killSwitch.Enable(); err != nil {
			return fmt.Errorf("failed to enable kill switch: %w", err)
		}
	}

	if fm.config.SplitTunneling {
		if err := fm.splitTunnel.Enable(); err != nil {
			return fmt.Errorf("failed to enable split tunneling: %w", err)
		}
	}

	if fm.config.DNSLeakProtection {
		if err := fm.dnsLeak.Enable(); err != nil {
			return fmt.Errorf("failed to enable DNS leak protection: %w", err)
		}
	}

	fm.running = true

	for _, ip := range fm.config.ProtocolWhitelist {
		fm.splitTunnel.AddIncludedIP(ip)
	}

	return nil
}

func (fm *FeatureManager) Stop(ctx context.Context) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if !fm.running {
		return nil
	}

	if fm.config.KillSwitch {
		fm.killSwitch.Disable()
	}

	if fm.config.SplitTunneling {
		fm.splitTunnel.Disable()
	}

	if fm.config.DNSLeakProtection {
		fm.dnsLeak.Disable()
	}

	fm.running = false
	close(fm.stopChan)
	fm.stopChan = make(chan struct{})

	return nil
}

func (fm *FeatureManager) UpdateConfig(cfg *config.FeaturesConfig) error {
	fm.mu.Lock()
	wasRunning := fm.running
	fm.mu.Unlock()

	if wasRunning {
		if err := fm.Stop(context.Background()); err != nil {
			return err
		}
	}

	fm.mu.Lock()
	fm.config = cfg
	fm.mu.Unlock()

	if wasRunning {
		return fm.Start(context.Background())
	}

	return nil
}

func (fm *FeatureManager) GetStatus() map[string]bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	return map[string]bool{
		"kill_switch":         fm.killSwitch.IsEnabled(),
		"split_tunneling":     fm.splitTunnel.IsEnabled(),
		"dns_leak_protection": fm.dnsLeak.IsEnabled(),
	}
}

func (fm *FeatureManager) GetKillSwitch() *KillSwitch {
	return fm.killSwitch
}

func (fm *FeatureManager) GetSplitTunnel() *SplitTunnel {
	return fm.splitTunnel
}

func (fm *FeatureManager) GetDNSLeakProtection() *DNSLeakProtection {
	return fm.dnsLeak
}

func (fm *FeatureManager) IsRunning() bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return fm.running
}
