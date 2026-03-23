package wireguard

import (
	"fmt"
	"slices"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newLink(name string) (netlink.Link, error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	link := &netlink.Wireguard{LinkAttrs: attrs}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, err
	}

	// Resolve the link after creation to get the index.
	return netlink.LinkByName(name)
}

func Add(ifName string, conf *config.Config) error {
	addr, wg, err := conf.Wireguard()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	link, err := newLink(ifName)
	if err != nil {
		_ = netlink.LinkDel(link)
		return fmt.Errorf("failed to create link: %v", err)
	}
	return setup(link, ifName, addr, wg)
}

// setup creates and configures a WireGuard interface inside the current network namespace.
// Must be called from within an ns.Do() closure.
func setup(link netlink.Link, ifName string, addr *netlink.Addr, conf *wgtypes.Config) error {
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("adding address: %w", err)
	}
	if err := configureDevice(ifName, *conf); err != nil {
		return fmt.Errorf("configuring device: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("setting link up: %w", err)
	}

	for _, peer := range conf.Peers {
		for _, allowedIP := range peer.AllowedIPs {
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       &allowedIP,
			}); err != nil {
				return fmt.Errorf("adding route: %w", err)
			}
		}
	}

	return nil
}

// configureDevice opens a wgctrl client and applies the WireGuard configuration.
// Must be called from within an ns.Do() closure.
func configureDevice(ifName string, conf wgtypes.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.ConfigureDevice(ifName, conf)
}

// Teardown removes the WireGuard interface. Idempotent: not-found is not an error.
// Must be called from within an ns.Do() closure.
func Teardown(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("failed to find link %s: %v", ifName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", ifName, err)
	}

	return nil
}

// Check verifies that the WireGuard interface exists, has the configured address,
// and that the device public key matches the configured private key.
// Must be called from within an ns.Do() closure.
func Check(ifName string, addr *netlink.Addr, pubKey wgtypes.Key) error {
	if exists, err := containsAddr(ifName, addr); err != nil {
		return fmt.Errorf("check: %w", err)
	} else if !exists {
		return fmt.Errorf("address %s not found on %s", addr, ifName)
	}

	if hasKey, err := hasPublicKey(ifName, pubKey); err != nil {
		return fmt.Errorf("check: %w", err)
	} else if !hasKey {
		return fmt.Errorf("public key mismatch on %s", ifName)
	}

	return nil
}

func containsAddr(ifName string, addr *netlink.Addr) (bool, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return false, fmt.Errorf("link by name: %w", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return false, fmt.Errorf("ip addr show: %w", err)
	}

	return slices.ContainsFunc(addrs, func(a netlink.Addr) bool {
		return a.IP.Equal(addr.IP)
	}), nil
}

func hasPublicKey(ifName string, pubKey wgtypes.Key) (bool, error) {
	if device, err := getDevice(ifName); err != nil {
		return false, err
	} else {
		return device.PublicKey == pubKey, nil
	}
}

func getDevice(ifName string) (*wgtypes.Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Device(ifName)
}
