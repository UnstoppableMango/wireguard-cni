package wireguard

import (
	"fmt"
	"net"
	"slices"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Add(mgr network.LinkManager, conf *config.Config) error {
	addr, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	zap.L().Info("creating wireguard link")
	link, err := mgr.Create()
	if err != nil {
		return fmt.Errorf("failed to add link: %w", err)
	}

	zap.L().Info("configuring wireguard link")
	if err := setup(link, addr, wg); err != nil {
		_ = mgr.Delete()
		return fmt.Errorf("failed to setup link: %w", err)
	}

	zap.L().Info("wireguard link ready")
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

	zap.L().Info("checking link address", zap.String("expected", addr.String()))
	addrs, err := link.Addresses()
	if err != nil {
		return fmt.Errorf("check: %w", err)
	}
	if !slices.ContainsFunc(addrs, func(a *net.IPNet) bool {
		return a.String() == addr.String()
	}) {
		return fmt.Errorf("address %s not found on link", addr)
	}

	zap.L().Info("checking link public key")
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
	zap.L().Info("assigning address", zap.String("address", addr.String()))
	if err := link.AssignAddress(addr); err != nil {
		return fmt.Errorf("assigning address: %w", err)
	}

	zap.L().Info("applying wireguard configuration")
	if err := link.ConfigureWireGuard(*conf); err != nil {
		return fmt.Errorf("configuring device: %w", err)
	}

	zap.L().Info("bringing link up")
	if err := link.BringUp(); err != nil {
		return fmt.Errorf("setting link up: %w", err)
	}

	for _, peer := range conf.Peers {
		for _, ip := range peer.AllowedIPs {
			zap.L().Info("adding route", zap.String("dst", ip.String()))
			if err := link.AddRoute(new(ip)); err != nil {
				return fmt.Errorf("adding route: %w", err)
			}
		}
	}
	return nil
}
