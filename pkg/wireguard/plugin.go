package wireguard

import (
	"fmt"
	"net"
	"slices"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Add(ifName string, conf *config.Config) error {
	addr, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	mgr := network.New(ifName)
	link, err := mgr.Create()
	if err != nil {
		return fmt.Errorf("failed to add link: %v", err)
	}
	if err := setup(link, addr, wg); err != nil {
		_ = mgr.Delete()
		return fmt.Errorf("failed to setup link: %v", err)
	}
	return nil
}

// Delete removes the WireGuard interface. Idempotent: not-found is not an error.
// Must be called from within an ns.Do() closure.
func Delete(ifName string) error {
	if err := network.New(ifName).Delete(); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", ifName, err)
	}
	return nil
}

// Check verifies that the WireGuard interface exists, has the configured address,
// and that the device public key matches the configured private key.
// Must be called from within an ns.Do() closure.
func Check(ifName string, conf *config.Config) error {
	addr, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	link, err := network.New(ifName).Get()
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
		return fmt.Errorf("address %s not found on %s", addr, ifName)
	}
	key, err := link.PublicKey()
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}
	if key != wg.PrivateKey.PublicKey() {
		return fmt.Errorf("public key mismatch on %s", ifName)
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
		for _, ip := range peer.AllowedIPs {
			if err := link.AddRoute(&ip); err != nil {
				return fmt.Errorf("adding route: %w", err)
			}
		}
	}
	return nil
}
