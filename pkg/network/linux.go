//go:build linux

package network

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

// New returns a LinkManager for the named network interface.
func New(name string) LinkManager {
	return netlinkManager(name)
}

// netlinkManager implements LinkManager. The string value is the interface name.
type netlinkManager string

func (m netlinkManager) Name() string {
	return string(m)
}

func (m netlinkManager) Create() (Link, error) {
	if err := netlink.LinkAdd(m.newLink()); err != nil {
		return nil, err
	}

	// look up the link we just created to get its index
	if link, err := m.Get(); err != nil {
		// best effort cleanup on failure
		_ = m.Delete()
		return nil, err
	} else {
		return link, nil
	}
}

func (m netlinkManager) newLink() netlink.Link {
	la := netlink.NewLinkAttrs()
	la.Name = m.Name()
	return &netlink.Wireguard{LinkAttrs: la}
}

func (m netlinkManager) Delete() error {
	link, err := m.get()
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func (m netlinkManager) get() (netlink.Link, error) {
	return netlink.LinkByName(string(m))
}

func (m netlinkManager) Get() (Link, error) {
	link, err := m.get()
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil, fmt.Errorf("%w: %w", ErrLinkNotFound, err)
	}
	if err != nil {
		return nil, err
	}
	return &netlinkLink{link}, nil
}

// netlinkLink implements Link wrapping a resolved netlink.Link.
type netlinkLink struct{ link netlink.Link }

func (l *netlinkLink) Name() string {
	return l.link.Attrs().Name
}

func (l *netlinkLink) String() string {
	return l.Name()
}

func (l *netlinkLink) AssignAddress(addr *net.IPNet) error {
	return netlink.AddrAdd(l.link, &netlink.Addr{IPNet: addr})
}

func (l *netlinkLink) BringUp() error {
	return netlink.LinkSetUp(l.link)
}

func (l *netlinkLink) AddRoute(dst *net.IPNet) error {
	err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: l.link.Attrs().Index,
		Dst:       dst,
	})
	if errors.Is(err, syscall.EEXIST) {
		return nil
	}
	return err
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
