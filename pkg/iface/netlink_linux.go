//go:build linux

package iface

import (
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type wgNS struct {
	h *netlink.Handle
}

func NsByPath(path string) (NS, error) {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return nil, err
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, err
	}
	return &wgNS{h: h}, nil
}

func (ns *wgNS) Create(name string) (l Link, err error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	var link netlink.Link = &netlink.Wireguard{
		LinkAttrs: attrs,
	}
	if err = ns.h.LinkAdd(link); err != nil {
		return nil, err
	}

	// look up the newly created link to get its interface index
	if link, err = ns.h.LinkByName(name); err != nil {
		return nil, err
	}
	return &wgLink{l: link, h: ns.h}, nil
}

func (ns *wgNS) Get(name string) (l Link, err error) {
	link, err := ns.h.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return &wgLink{l: link, h: ns.h}, nil
}

func Create(name string) (l Link, err error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}
	ns := &wgNS{h: h}
	return ns.Create(name)
}

type wgLink struct {
	l netlink.Link
	h *netlink.Handle
}

func (l *wgLink) AddRoute(route string) (Route, error) {
	ipNet, err := netlink.ParseIPNet(route)
	if err != nil {
		return nil, err
	}

	r := netlink.Route{
		LinkIndex: l.Index(),
		Dst:       ipNet,
		Scope:     unix.RT_SCOPE_LINK,
	}
	if err = l.h.RouteAdd(&r); err != nil {
		return nil, err
	}
	return &wgRoute{r: r}, nil
}

func (l *wgLink) Routes() ([]Route, error) {
	var result []Route
	// TODO: verify this works the way I think it does
	err := l.h.RouteListFilteredIter(
		netlink.FAMILY_ALL,
		&netlink.Route{LinkIndex: l.Index()},
		netlink.RT_FILTER_OIF,
		func(r netlink.Route) (cont bool) {
			result = append(result, wgRoute{r: r})
			return true
		},
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// AssignAddr implements [Link].
func (l *wgLink) AssignAddr(addr net.IPNet) error {
	a, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return err
	}
	return netlink.AddrAdd(l.l, a)
}

func (l *wgLink) Index() int {
	return l.l.Attrs().Index
}

func (l *wgLink) Mac() net.HardwareAddr {
	return l.l.Attrs().HardwareAddr
}

// MoveTo implements [Link].
func (l *wgLink) MoveTo(netNs string) (Link, error) {
	ns, err := netns.GetFromPath(netNs)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetNsFd(l.l, int(ns)); err != nil {
		return nil, err
	}
	return &wgLink{l: l.l, h: l.h}, nil
}

// SetUp implements [Link].
func (l *wgLink) SetUp() error {
	return l.h.LinkSetUp(l.l)
}

type wgRoute struct {
	r netlink.Route
}

func (r wgRoute) Dst() net.IPNet {
	return *r.r.Dst
}

func (r wgRoute) Scope() int {
	return int(r.r.Scope)
}

type wgClient struct{}

func NewClient() Client {
	return &wgClient{}
}

func (c *wgClient) Create(ifName string) (Link, error) {
	return Create(ifName)
}

func (c *wgClient) NsByPath(path string) (NS, error) {
	return NsByPath(path)
}
