//go:build linux

package main

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
)

// parseAddress parses a CIDR string preserving the host IP (not the network address).
func parseAddress(cidr string) (*netlink.Addr, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %v", cidr, err)
	}
	return &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: ipnet.Mask}}, nil
}

// addPeerRoutes adds a route for each peer AllowedIP via the given link.
func addPeerRoutes(link netlink.Link, peers []PeerConfig) error {
	for _, peer := range peers {
		for _, allowedIP := range peer.AllowedIPs {
			_, dst, err := net.ParseCIDR(allowedIP)
			if err != nil {
				return fmt.Errorf("invalid allowedIP %q: %v", allowedIP, err)
			}
			route := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       dst,
			}
			if err := netlink.RouteAdd(route); err != nil {
				return fmt.Errorf("failed to add route for %s: %v", allowedIP, err)
			}
		}
	}
	return nil
}

// buildCNIResult constructs the CNI result for a WireGuard interface.
// WireGuard uses AllowedIPs for routing so no gateway is set.
func buildCNIResult(cniVersion, ifName, netnsPath, address string) (*current.Result, error) {
	ip, ipnet, err := net.ParseCIDR(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %v", address, err)
	}

	ifIdx := 0
	result := &current.Result{
		CNIVersion: cniVersion,
		Interfaces: []*current.Interface{
			{
				Name:    ifName,
				Sandbox: netnsPath,
			},
		},
		IPs: []*current.IPConfig{
			{
				Interface: current.Int(ifIdx),
				Address: net.IPNet{
					IP:   ip,
					Mask: ipnet.Mask,
				},
			},
		},
		Routes: []*types.Route{},
	}

	return result, nil
}
