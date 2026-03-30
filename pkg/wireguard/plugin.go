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

	zap.L().Info("looking up wireguard link")
	link, err := mgr.Get()
	if err != nil && !network.IsNotFound(err) {
		return fmt.Errorf("get link: %w", err)
	}

	if err == nil {
		// Interface already exists — reconfigure it.
		zap.L().Info("reconfiguring existing wireguard link")
		if err := reconfigure(link, addr, wg); err != nil {
			return fmt.Errorf("reconfigure link %s: %w", link, err)
		}
	} else {
		// Interface not found — create and set up fresh.
		zap.L().Info("creating wireguard link")
		link, err = mgr.Create()
		if err != nil {
			return fmt.Errorf("create link: %w", err)
		}

		zap.L().Info("configuring wireguard link")
		if err := setup(link, addr, wg); err != nil {
			_ = mgr.Delete()
			return fmt.Errorf("setup link %s: %w", link, err)
		}
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
		return fmt.Errorf("check link: %w", err)
	}

	zap.L().Info("checking link address", zap.String("expected", addr.String()))
	addrs, err := link.Addresses()
	if err != nil {
		return fmt.Errorf("check link %s: %w", link, err)
	}
	if !slices.ContainsFunc(addrs, func(a *net.IPNet) bool {
		return a.String() == addr.String()
	}) {
		return fmt.Errorf("check link %s: address %s not found", link, addr)
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

func setup(link network.Link, addr *net.IPNet, conf *wgtypes.Config) error {
	zap.L().Info("assigning address", zap.String("address", addr.String()))
	if err := link.AssignAddress(addr); err != nil {
		return fmt.Errorf("assign address %v: %w", addr, err)
	}
	return applyConfig(link, conf)
}

// reconfigure applies the desired configuration to an existing WireGuard link.
// Unlike setup, it only assigns the address if not already present, since other
// plugins in the chain may have already assigned addresses to the interface.
func reconfigure(link network.Link, addr *net.IPNet, conf *wgtypes.Config) error {
	zap.L().Info("checking existing addresses")
	addrs, err := link.Addresses()
	if err != nil {
		return fmt.Errorf("get addresses %v: %w", link, err)
	}

	hasAddr := slices.ContainsFunc(addrs, func(a *net.IPNet) bool {
		return a.String() == addr.String()
	})
	if !hasAddr {
		zap.L().Info("assigning address", zap.String("address", addr.String()))
		if err := link.AssignAddress(addr); err != nil {
			return fmt.Errorf("assign address %v: %w", addr, err)
		}
	}

	return applyConfig(link, conf)
}

// applyConfig configures the WireGuard device, brings the link up, and installs
// per-peer routes. It is shared by setup (fresh interface) and reconfigure (existing).
func applyConfig(link network.Link, conf *wgtypes.Config) error {
	zap.L().Info("applying wireguard configuration")
	if err := link.ConfigureWireGuard(*conf); err != nil {
		return fmt.Errorf("configure device %v: %w", link, err)
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
