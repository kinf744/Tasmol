package features

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type DNSLeakProtection struct {
	mu            sync.RWMutex
	enabled       bool
	interfaceName string
	vpnGateway    string
	dnsServers    []string
	originalDNS   []string
	originalRoutes []netlink.Route
	monitoring    bool
	stopChan      chan struct{}
}

func NewDNSLeakProtection(interfaceName, vpnGateway string, dnsServers []string) *DNSLeakProtection {
	return &DNSLeakProtection{
		enabled:       false,
		interfaceName: interfaceName,
		vpnGateway:    vpnGateway,
		dnsServers:    dnsServers,
		stopChan:      make(chan struct{}),
	}
}

func (dlp *DNSLeakProtection) Enable() error {
	dlp.mu.Lock()
	defer dlp.mu.Unlock()

	if dlp.enabled {
		return nil
	}

	if err := dlp.saveOriginalState(); err != nil {
		return fmt.Errorf("failed to save original state: %w", err)
	}

	if err := dlp.applyProtection(); err != nil {
		dlp.restoreOriginalState()
		return fmt.Errorf("failed to apply DNS leak protection: %w", err)
	}

	dlp.enabled = true
	dlp.startMonitoring()
	return nil
}

func (dlp *DNSLeakProtection) Disable() error {
	dlp.mu.Lock()
	defer dlp.mu.Unlock()

	if !dlp.enabled {
		return nil
	}

	dlp.stopMonitoring()
	if err := dlp.restoreOriginalState(); err != nil {
		return fmt.Errorf("failed to restore original state: %w", err)
	}

	dlp.enabled = false
	return nil
}

func (dlp *DNSLeakProtection) IsEnabled() bool {
	dlp.mu.RLock()
	defer dlp.mu.RUnlock()
	return dlp.enabled
}

func (dlp *DNSLeakProtection) saveOriginalState() error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
	}, netlink.RT_FILTER_DST)
	if err != nil {
		return err
	}
	dlp.originalRoutes = routes

	return nil
}

func (dlp *DNSLeakProtection) applyProtection() error {
	link, err := netlink.LinkByName(dlp.interfaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	for _, dns := range dlp.dnsServers {
		ip := net.ParseIP(dns)
		if ip == nil {
			continue
		}

		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			},
			Gw:    net.ParseIP(dlp.vpnGateway),
			Scope: netlink.SCOPE_UNIVERSE,
		}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("failed to add DNS route: %w", err)
		}
	}

	blockRule := netlink.NewRule()
	blockRule.Table = unix.RT_TABLE_UNSPEC
	blockRule.Priority = 32765
	blockRule.Mask = 0
	blockRule.Family = netlink.FAMILY_V4
	blockRule.Action = netlink.RULE_ACTION_UNREACHABLE
	blockRule.Src = &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)}

	if err := netlink.RuleAdd(blockRule); err != nil {
		return fmt.Errorf("failed to add DNS block rule: %w", err)
	}

	return nil
}

func (dlp *DNSLeakProtection) restoreOriginalState() error {
	rules, _ := netlink.RuleList(netlink.FAMILY_V4)
	for _, rule := range rules {
		if rule.Priority == 32765 {
			netlink.RuleDel(&rule)
		}
	}

	for _, route := range dlp.originalRoutes {
		netlink.RouteReplace(&route)
	}

	return nil
}

func (dlp *DNSLeakProtection) startMonitoring() {
	dlp.monitoring = true
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-dlp.stopChan:
				return
			case <-ticker.C:
				dlp.checkDNSLeak()
			}
		}
	}()
}

func (dlp *DNSLeakProtection) stopMonitoring() {
	dlp.monitoring = false
	close(dlp.stopChan)
	dlp.stopChan = make(chan struct{})
}

func (dlp *DNSLeakProtection) checkDNSLeak() {
	dlp.mu.RLock()
	enabled := dlp.enabled
	dlp.mu.RUnlock()

	if !enabled {
		return
	}

	for _, dns := range dlp.dnsServers {
		conn, err := net.DialTimeout("udp", dns+":53", 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		localAddr := conn.LocalAddr().(*net.UDPAddr)
		if localAddr.IP.IsLoopback() || localAddr.IP.IsUnspecified() {
			continue
		}
	}
}