package wireguard

import (
	"fmt"
	"net"
	"slices"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Add(mgr network.LinkManager, conf *config.Config) error {
	addr, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	link, err := mgr.Create()
	if err != nil {
		return fmt.Errorf("failed to add link: %w", err)
	}
	if err := setup(link, addr, wg); err != nil {
		_ = mgr.Delete()
		return fmt.Errorf("failed to setup link: %w", err)
	}
	return nil
}

// Check verifies that the WireGuard interface exists, has the configured address,
// and that the device public key matches the configured private key.
// Must be called from within an ns.Do() closure.
func Check(mgr network.LinkManager, conf *config.Config) error {
	addr, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	link, err := mgr.Get()
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}
	addrs, err := link.Addresses()
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}
	if !slices.ContainsFunc(addrs, func(a *net.IPNet) bool {
		return a.String() == addr.String()
	}) {
		return fmt.Errorf("address %s not found on link", addr)
	}
	key, err := link.PublicKey()
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}
	if key != wg.PrivateKey.PublicKey() {
		return fmt.Errorf("public key mismatch on link")
	}
	return nil
}

func setup(link network.Link, addr *net.IPNet, conf *wgtypes.Config) error {
	if err := link.AssignAddress(addr); err != nil {
		return fmt.Errorf("adding address: %w", err)
	}
	if err := link.ConfigureWireGuard(*conf); err != nil {
		return fmt.Errorf("configuring device: %w", err)
	}
	if err := link.BringUp(); err != nil {
		return fmt.Errorf("setting link up: %w", err)
	}
	for _, peer := range conf.Peers {
		for i := range peer.AllowedIPs {
			if err := link.AddRoute(&peer.AllowedIPs[i]); err != nil {
				return fmt.Errorf("adding route: %w", err)
			}
		}
	}
	return nil
}
