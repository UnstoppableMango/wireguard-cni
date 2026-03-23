//go:build linux

package network

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// New returns a LinkManager for the named network interface.
func New(name string) LinkManager {
	return netlinkManager(name)
}

// netlinkManager implements LinkManager. The string value is the interface name.
type netlinkManager string

func (m netlinkManager) Create() (Link, error) {
	la := netlink.NewLinkAttrs()
	la.Name = string(m)
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(string(m))
	if err != nil {
		return nil, err
	}
	return &netlinkLink{link}, nil
}

func (m netlinkManager) Delete() error {
	link, err := netlink.LinkByName(string(m))
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return err
	}
	return netlink.LinkDel(link)
}

func (m netlinkManager) Get() (Link, error) {
	link, err := netlink.LinkByName(string(m))
	if err != nil {
		return nil, err
	}
	return &netlinkLink{link}, nil
}

// netlinkLink implements Link wrapping a resolved netlink.Link.
type netlinkLink struct{ link netlink.Link }

func (l *netlinkLink) AssignAddress(addr *net.IPNet) error {
	return netlink.AddrAdd(l.link, &netlink.Addr{IPNet: addr})
}

func (l *netlinkLink) BringUp() error {
	return netlink.LinkSetUp(l.link)
}

func (l *netlinkLink) AddRoute(dst *net.IPNet) error {
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: l.link.Attrs().Index,
		Dst:       dst,
	})
}

func (l *netlinkLink) Addresses() ([]*net.IPNet, error) {
	addrs, err := netlink.AddrList(l.link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	result := make([]*net.IPNet, len(addrs))
	for i, a := range addrs {
		result[i] = a.IPNet
	}
	return result, nil
}

func (l *netlinkLink) ConfigureWireGuard(conf wgtypes.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.ConfigureDevice(l.link.Attrs().Name, conf)
}

func (l *netlinkLink) PublicKey() (wgtypes.Key, error) {
	client, err := wgctrl.New()
	if err != nil {
		return wgtypes.Key{}, err
	}
	defer client.Close()
	dev, err := client.Device(l.link.Attrs().Name)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return dev.PublicKey, nil
}
