package wireguard

import (
	"fmt"
	"net"
	"slices"

	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Name string

func (n Name) String() string { return string(n) }

func (n Name) Add(addr *net.IPNet, conf *wgtypes.Config) (err error) {
	mgr := network.New(n.String())
	link, err := mgr.Create()
	if err != nil {
		return fmt.Errorf("failed to add link: %v", err)
	}
	if err := n.setup(link, addr, conf); err != nil {
		_ = mgr.Delete()
		return fmt.Errorf("failed to setup link: %v", err)
	}
	return nil
}

// setup creates and configures a WireGuard interface inside the current network namespace.
// Must be called from within an ns.Do() closure.
func (n Name) setup(link network.Link, addr *net.IPNet, conf *wgtypes.Config) error {
	if err := link.AssignAddress(addr); err != nil {
		return fmt.Errorf("adding address: %w", err)
	}
	if err := n.configureDevice(*conf); err != nil {
		return fmt.Errorf("configuring device: %w", err)
	}
	if err := link.BringUp(); err != nil {
		return fmt.Errorf("setting link up: %w", err)
	}
	for _, peer := range conf.Peers {
		for _, allowedIP := range peer.AllowedIPs {
			allowedIP := allowedIP
			if err := link.AddRoute(&allowedIP); err != nil {
				return fmt.Errorf("adding route: %w", err)
			}
		}
	}
	return nil
}

// configureDevice opens a wgctrl client and applies the WireGuard configuration.
// Must be called from within an ns.Do() closure.
func (n Name) configureDevice(conf wgtypes.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.ConfigureDevice(n.String(), conf)
}

// Check verifies that the WireGuard interface exists, has the configured address,
// and that the device public key matches the configured private key.
// Must be called from within an ns.Do() closure.
func (n Name) Check(addr *net.IPNet, pubKey wgtypes.Key) error {
	if exists, err := n.containsAddr(addr); err != nil {
		return fmt.Errorf("check: %w", err)
	} else if !exists {
		return fmt.Errorf("address %s not found on %s", addr, n.String())
	}

	if hasKey, err := n.hasPublicKey(pubKey); err != nil {
		return fmt.Errorf("check: %w", err)
	} else if !hasKey {
		return fmt.Errorf("public key mismatch on %s", n.String())
	}

	return nil
}

func (n Name) containsAddr(addr *net.IPNet) (bool, error) {
	link, err := network.New(n.String()).Get()
	if err != nil {
		return false, fmt.Errorf("link by name: %w", err)
	}
	addrs, err := link.Addresses()
	if err != nil {
		return false, fmt.Errorf("ip addr show: %w", err)
	}
	return slices.ContainsFunc(addrs, func(a *net.IPNet) bool {
		return a.String() == addr.String()
	}), nil
}

func (n Name) hasPublicKey(pubKey wgtypes.Key) (bool, error) {
	if device, err := n.getDevice(); err != nil {
		return false, err
	} else {
		return device.PublicKey == pubKey, nil
	}
}

func (n Name) getDevice() (*wgtypes.Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Device(n.String())
}

// Delete removes the WireGuard interface. Idempotent: not-found is not an error.
// Must be called from within an ns.Do() closure.
func (n Name) Delete() error {
	if err := network.New(n.String()).Delete(); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", n, err)
	}
	return nil
}
