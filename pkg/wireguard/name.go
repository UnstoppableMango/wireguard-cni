package wireguard

import (
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Name string

func (n Name) String() string { return string(n) }

func (n Name) Add(addr *netlink.Addr, conf *wgtypes.Config) (err error) {
	link := n.newLink()
	if err = netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to add link: %v", err)
	}

	// Resolve the link after creation to get the index.
	if link, err = n.link(); err != nil {
		return fmt.Errorf("failed to create link: %v", err)
	}

	if err := n.setup(link, addr, conf); err != nil {
		_ = netlink.LinkDel(link)
		return fmt.Errorf("failed to setup link: %v", err)
	}

	return nil
}

func (n Name) newLink() netlink.Link {
	link := &netlink.Wireguard{
		LinkAttrs: netlink.NewLinkAttrs(),
	}
	link.Name = n.String()
	return link
}

// setup creates and configures a WireGuard interface inside the current network namespace.
// Must be called from within an ns.Do() closure.
func (n Name) setup(link netlink.Link, addr *netlink.Addr, conf *wgtypes.Config) error {
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("adding address: %w", err)
	}
	if err := n.configureDevice(*conf); err != nil {
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
func (n Name) Check(addr *netlink.Addr, pubKey wgtypes.Key) error {
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

func (n Name) containsAddr(addr *netlink.Addr) (bool, error) {
	link, err := n.link()
	if err != nil {
		return false, fmt.Errorf("link by name: %w", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return false, fmt.Errorf("ip addr show: %w", err)
	}

	return slices.ContainsFunc(addrs, addr.Equal), nil
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
	link, err := n.link()
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("failed to find link %s: %v", n, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", n, err)
	}

	return nil
}

func (n Name) link() (netlink.Link, error) {
	return netlink.LinkByName(n.String())
}
