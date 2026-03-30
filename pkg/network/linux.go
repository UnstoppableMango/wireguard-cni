//go:build linux

package network

import (
	"errors"
	"fmt"
	"math"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
		return nil, errors.Join(ErrLinkNotFound, err)
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

func (l *netlinkLink) Routes() ([]*net.IPNet, error) {
	routes, err := netlink.RouteList(l.link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	result := make([]*net.IPNet, 0, len(routes))
	for _, r := range routes {
		if r.Dst != nil {
			result = append(result, r.Dst)
			continue
		}
		// In netlink, a nil Dst represents a default route.
		// Map to an explicit /0 network based on the route family.
		var cidr string
		switch r.Family {
		case netlink.FAMILY_V4:
			cidr = "0.0.0.0/0"
		case netlink.FAMILY_V6:
			cidr = "::/0"
		default:
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		result = append(result, ipNet)
	}
	return result, nil
}

func (l *netlinkLink) SetMAC(mac net.HardwareAddr) error {
	return netlink.LinkSetHardwareAddr(l.link, mac)
}

// SetBandwidth applies ingress and egress rate limits to the link using tc qdiscs.
// Rates are in bits per second; bursts are in bits.
// Egress limiting uses a TBF qdisc on the root.
// Ingress limiting uses an ingress qdisc with a U32 filter and police action.
func (l *netlinkLink) SetBandwidth(ingressRate, ingressBurst, egressRate, egressBurst uint64) error {
	const maxUint32 = uint64(math.MaxUint32)
	idx := l.link.Attrs().Index

	if egressRate > 0 {
		// Convert bits/s → bytes/s and bits → bytes.
		rateBytes := egressRate / 8
		if rateBytes == 0 {
			return fmt.Errorf("egress rate %d bps is too low (minimum 8 bps)", egressRate)
		}
		if egressBurst/8 > maxUint32 {
			return fmt.Errorf("egress burst %d bits overflows uint32", egressBurst)
		}
		burstBytes := uint32(egressBurst / 8)
		// Limit: how many bytes can be queued — use burst as a sensible default.
		limitBytes := burstBytes
		if limitBytes == 0 {
			// Fall back: ~100ms of traffic at the given rate.
			if rateBytes/10 > maxUint32 {
				return fmt.Errorf("egress rate %d bps derived limit overflows uint32", egressRate)
			}
			limitBytes = uint32(rateBytes / 10)
		}
		tbf := &netlink.Tbf{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: idx,
				Handle:    netlink.MakeHandle(1, 0),
				Parent:    netlink.HANDLE_ROOT,
			},
			Rate:   rateBytes,
			Buffer: burstBytes,
			Limit:  limitBytes,
		}
		if err := netlink.QdiscReplace(tbf); err != nil {
			return err
		}
	}

	if ingressRate > 0 {
		if ingressRate/8 > maxUint32 {
			return fmt.Errorf("ingress rate %d bps overflows uint32", ingressRate)
		}
		rateBytes := ingressRate / 8
		if rateBytes == 0 {
			return fmt.Errorf("ingress rate %d bps is too low (minimum 8 bps)", ingressRate)
		}
		if ingressBurst/8 > maxUint32 {
			return fmt.Errorf("ingress burst %d bits overflows uint32", ingressBurst)
		}

		// Add ingress qdisc; delete and retry if one already exists.
		ingress := &netlink.Ingress{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: idx,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
		if err := netlink.QdiscAdd(ingress); err != nil {
			if errors.Is(err, syscall.EEXIST) || errors.Is(err, unix.EEXIST) {
				if delErr := netlink.QdiscDel(ingress); delErr != nil &&
					!errors.Is(delErr, syscall.ENOENT) && !errors.Is(delErr, unix.ENOENT) {
					return delErr
				}
				if addErr := netlink.QdiscAdd(ingress); addErr != nil {
					return addErr
				}
			} else {
				return err
			}
		}

		// Add U32 filter with police action to drop excess traffic.
		police := netlink.NewPoliceAction()
		police.Rate = uint32(rateBytes)
		police.Burst = uint32(ingressBurst / 8)
		police.ExceedAction = netlink.TC_POLICE_SHOT
		police.NotExceedAction = netlink.TC_POLICE_OK

		filter := &netlink.U32{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: idx,
				Parent:    netlink.MakeHandle(0xffff, 0),
				Priority:  1,
				Protocol:  unix.ETH_P_ALL,
			},
			Police: police,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			return err
		}
	}

	return nil
}
