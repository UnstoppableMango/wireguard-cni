package wireguard

import (
	"fmt"
	"net"
	"slices"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Add(mgr network.LinkManager, conf *config.Config) error {
	addrs, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	mac, err := conf.ParseMAC()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	zap.L().Info("looking up wireguard link")
	link, err := mgr.Get()
	if err != nil && !network.IsNotFound(err) {
		return fmt.Errorf("get link: %w", err)
	}

	if err != nil {
		zap.L().Info("creating wireguard link")
		link, err = mgr.Create()
		if err != nil {
			return fmt.Errorf("create link: %w", err)
		}
	}

	zap.L().Info("configuring wireguard link")
	if err := setup(link, addrs, wg, mac); err != nil {
		_ = mgr.Delete()
		return fmt.Errorf("setup link %s: %w", link, err)
	}

	if bw := conf.RuntimeConfig.Bandwidth; bw != nil {
		zap.L().Info("applying bandwidth limits")
		if err := link.SetBandwidth(bw.IngressRate, bw.IngressBurst, bw.EgressRate, bw.EgressBurst); err != nil {
			_ = mgr.Delete()
			return fmt.Errorf("set bandwidth: %w", err)
		}
	}

	zap.L().Info("wireguard link ready")
	return nil
}

// Check verifies that the WireGuard interface exists, that all IPs and routes
// from prevResult are still present in the live network namespace, and that the
// device public key matches the configured private key.
// Must be called from within an ns.Do() closure.
func Check(mgr network.LinkManager, conf *config.Config, ifName string, prevResult *current.Result) error {
	_, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if prevResult == nil {
		return fmt.Errorf("check: missing prevResult")
	}
	link, err := mgr.Get()
	if err != nil {
		return fmt.Errorf("check link: %w", err)
	}

	// Find our interface index in prevResult.
	ifIdx := -1
	for i, iface := range prevResult.Interfaces {
		if iface.Name == ifName {
			ifIdx = i
			break
		}
	}
	if ifIdx == -1 {
		return fmt.Errorf("check link %s: interface %s not found in prevResult", link, ifName)
	}

	// Verify IPs from prevResult are assigned.
	zap.L().Info("checking link addresses from prevResult")
	addrs, err := link.Addresses()
	if err != nil {
		return fmt.Errorf("check link %s: %w", link, err)
	}
	ipValidated := false
	for _, ipConf := range prevResult.IPs {
		if ipConf.Interface == nil || *ipConf.Interface != ifIdx {
			continue
		}
		ip := ipConf.Address
		if !slices.ContainsFunc(addrs, func(a *net.IPNet) bool {
			return a.String() == ip.String()
		}) {
			return fmt.Errorf("check link %s: address %s not found", link, ip.String())
		}
		ipValidated = true
	}
	if !ipValidated {
		return fmt.Errorf("check link %s: no IPs from prevResult matched interface %s", link, ifName)
	}

	// Verify routes this plugin is responsible for (peer AllowedIPs) are installed.
	// prevResult.Routes is not used here because it may include routes from other
	// plugins on other interfaces, which would not be present on the WireGuard link.
	var expectedRoutes []net.IPNet
	for _, peer := range wg.Peers {
		expectedRoutes = append(expectedRoutes, peer.AllowedIPs...)
	}
	if len(expectedRoutes) > 0 {
		zap.L().Info("checking link routes from peer AllowedIPs")
		routes, err := link.Routes()
		if err != nil {
			return fmt.Errorf("check link %s: %w", link, err)
		}
		for i := range expectedRoutes {
			dst := &expectedRoutes[i]
			if !slices.ContainsFunc(routes, func(r *net.IPNet) bool {
				return r.String() == dst.String()
			}) {
				return fmt.Errorf("check link %s: route %s not found", link, dst.String())
			}
		}
	}

	zap.L().Info("checking link public key")
	key, err := link.PublicKey()
	if err != nil {
		return fmt.Errorf("check link %s: %w", link, err)
	}
	if key != wg.PrivateKey.PublicKey() {
		return fmt.Errorf("check link %s: public key mismatch", link)
	}
	return nil
}

func setup(link network.Link, addrs []*net.IPNet, conf *wgtypes.Config, mac net.HardwareAddr) error {
	existing, err := link.Addresses()
	if err != nil {
		return fmt.Errorf("get existing addresses: %w", err)
	}

	for _, addr := range addrs {
		if slices.ContainsFunc(existing, func(a *net.IPNet) bool {
			return a.String() == addr.String()
		}) {
			continue
		}

		zap.L().Info("assigning address", zap.String("address", addr.String()))
		if err := link.AssignAddress(addr); err != nil {
			return fmt.Errorf("assign address %v: %w", addr, err)
		}
	}
	return applyConfig(link, conf, mac)
}

// applyConfig configures the WireGuard device, brings the link up, and installs
// per-peer routes. It is shared by setup (fresh interface) and reconfigure (existing).
func applyConfig(link network.Link, conf *wgtypes.Config, mac net.HardwareAddr) error {
	zap.L().Info("applying wireguard configuration")
	if err := link.ConfigureWireGuard(*conf); err != nil {
		return fmt.Errorf("configure device %v: %w", link, err)
	}

	if mac != nil {
		zap.L().Info("setting MAC address", zap.String("mac", mac.String()))
		if err := link.SetMAC(mac); err != nil {
			return fmt.Errorf("set MAC %s: %w", mac.String(), err)
		}
	}

	zap.L().Info("bringing link up")
	if err := link.BringUp(); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}

	for _, peer := range conf.Peers {
		for _, ip := range peer.AllowedIPs {
			zap.L().Info("adding route", zap.String("dst", ip.String()))
			if err := link.AddRoute(new(ip)); err != nil {
				return fmt.Errorf("add route %v: %w", ip, err)
			}
		}
	}
	return nil
}
