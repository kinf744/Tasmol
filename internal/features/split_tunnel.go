package features

import (
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

type SplitTunnel struct {
	mu           sync.RWMutex
	enabled      bool
	interfaceName string
	vpnGateway    string
	includedIPs   []*net.IPNet
	excludedIPs   []*net.IPNet
	includedPorts map[string]bool
	excludedPorts map[string]bool
	originalRoutes []netlink.Route
}

func NewSplitTunnel(interfaceName, vpnGateway string) *SplitTunnel {
	return &SplitTunnel{
		enabled:       false,
		interfaceName: interfaceName,
		vpnGateway:    vpnGateway,
		includedIPs:   make([]*net.IPNet, 0),
		excludedIPs:   make([]*net.IPNet, 0),
		includedPorts: make(map[string]bool),
		excludedPorts: make(map[string]bool),
	}
}

func (st *SplitTunnel) Enable() error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.enabled {
		return nil
	}

	if err := st.saveOriginalRoutes(); err != nil {
		return err
	}

	if err := st.applySplitTunnel(); err != nil {
		st.restoreRoutes()
		return err
	}

	st.enabled = true
	return nil
}

func (st *SplitTunnel) Disable() error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if !st.enabled {
		return nil
	}

	if err := st.restoreRoutes(); err != nil {
		return err
	}

	st.enabled = false
	return nil
}

func (st *SplitTunnel) IsEnabled() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.enabled
}

func (st *SplitTunnel) AddIncludedIP(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.includedIPs = append(st.includedIPs, ipNet)
	if st.enabled {
		return st.applySplitTunnel()
	}
	return nil
}

func (st *SplitTunnel) AddExcludedIP(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.excludedIPs = append(st.excludedIPs, ipNet)
	if st.enabled {
		return st.applySplitTunnel()
	}
	return nil
}

func (st *SplitTunnel) AddIncludedPort(port string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.includedPorts[port] = true
}

func (st *SplitTunnel) AddExcludedPort(port string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.excludedPorts[port] = true
}

func (st *SplitTunnel) saveOriginalRoutes() error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	st.originalRoutes = routes
	return nil
}

func (st *SplitTunnel) applySplitTunnel() error {
	link, err := netlink.LinkByName(st.interfaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	if len(st.includedIPs) > 0 {
		for _, ipNet := range st.includedIPs {
			route := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       ipNet,
				Gw:        net.ParseIP(st.vpnGateway),
				Scope:     netlink.SCOPE_UNIVERSE,
			}
			if err := netlink.RouteReplace(route); err != nil {
				return fmt.Errorf("failed to add included route: %w", err)
			}
		}
	} else {
		defaultRoute := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Gw:        net.ParseIP(st.vpnGateway),
		}
		if err := netlink.RouteReplace(defaultRoute); err != nil {
			return fmt.Errorf("failed to set default route: %w", err)
		}
	}

	for _, ipNet := range st.excludedIPs {
		route := &netlink.Route{
			Dst:   ipNet,
			Scope: netlink.SCOPE_LINK,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to add excluded route: %w", err)
		}
	}

	return nil
}

func (st *SplitTunnel) restoreRoutes() error {
	for _, route := range st.originalRoutes {
		netlink.RouteReplace(&route)
	}
	return nil
}

func (st *SplitTunnel) GetIncludedIPs() []string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	result := make([]string, len(st.includedIPs))
	for i, ipNet := range st.includedIPs {
		result[i] = ipNet.String()
	}
	return result
}

func (st *SplitTunnel) GetExcludedIPs() []string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	result := make([]string, len(st.excludedIPs))
	for i, ipNet := range st.excludedIPs {
		result[i] = ipNet.String()
	}
	return result
}