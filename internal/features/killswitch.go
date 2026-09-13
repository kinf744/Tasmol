package features

import (
	"fmt"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type KillSwitch struct {
	mu           sync.RWMutex
	enabled      bool
	originalRoutes []netlink.Route
	originalRules  []netlink.Rule
	interfaceName string
	vpnGateway    string
	monitoring   bool
	stopChan     chan struct{}
}

func NewKillSwitch(interfaceName, vpnGateway string) *KillSwitch {
	return &KillSwitch{
		enabled:       false,
		interfaceName: interfaceName,
		vpnGateway:    vpnGateway,
		stopChan:      make(chan struct{}),
	}
}

func (ks *KillSwitch) Enable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.enabled {
		return nil
	}

	if err := ks.saveOriginalState(); err != nil {
		return fmt.Errorf("failed to save original state: %w", err)
	}

	if err := ks.applyKillSwitch(); err != nil {
		ks.restoreOriginalState()
		return fmt.Errorf("failed to apply kill switch: %w", err)
	}

	ks.enabled = true
	ks.startMonitoring()
	return nil
}

func (ks *KillSwitch) Disable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.enabled {
		return nil
	}

	ks.stopMonitoring()
	if err := ks.restoreOriginalState(); err != nil {
		return fmt.Errorf("failed to restore original state: %w", err)
	}

	ks.enabled = false
	return nil
}

func (ks *KillSwitch) IsEnabled() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.enabled
}

func (ks *KillSwitch) saveOriginalState() error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	ks.originalRoutes = routes

	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	ks.originalRules = rules

	return nil
}

func (ks *KillSwitch) applyKillSwitch() error {
	link, err := netlink.LinkByName(ks.interfaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	defaultRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        net.ParseIP(ks.vpnGateway),
	}

	if err := netlink.RouteReplace(defaultRoute); err != nil {
		return fmt.Errorf("failed to set default route: %w", err)
	}

	blockRule := netlink.NewRule()
	blockRule.Table = unix.RT_TABLE_UNSPEC
	blockRule.Priority = 32766
	blockRule.Mask = 0
	blockRule.Family = netlink.FAMILY_V4
	blockRule.Action = netlink.RULE_ACTION_UNREACHABLE

	if err := netlink.RuleAdd(blockRule); err != nil {
		return fmt.Errorf("failed to add block rule: %w", err)
	}

	return nil
}

func (ks *KillSwitch) restoreOriginalState() error {
	for _, rule := range ks.originalRules {
		netlink.RuleDel(&rule)
	}

	for _, route := range ks.originalRoutes {
		netlink.RouteReplace(&route)
	}

	return nil
}

func (ks *KillSwitch) startMonitoring() {
	ks.monitoring = true
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ks.stopChan:
				return
			case <-ticker.C:
				ks.checkVPNConnection()
			}
		}
	}()
}

func (ks *KillSwitch) stopMonitoring() {
	ks.monitoring = false
	close(ks.stopChan)
	ks.stopChan = make(chan struct{})
}

func (ks *KillSwitch) checkVPNConnection() {
	ks.mu.RLock()
	enabled := ks.enabled
	ks.mu.RUnlock()

	if !enabled {
		return
	}

	link, err := netlink.LinkByName(ks.interfaceName)
	if err != nil || link.Attrs().OperState != netlink.OperUp {
		ks.Disable()
	}
}