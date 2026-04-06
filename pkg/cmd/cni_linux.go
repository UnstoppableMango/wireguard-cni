//go:build linux

package cmd

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
)

func Add(args *skel.CmdArgs) error {
	cni, err := wireguard.FromBytes(args.StdinData)
	if err != nil {
		return fmt.Errorf("new cni: %w", err)
	}
	return cni.Add(args.Netns, args.IfName)
}

func Check(args *skel.CmdArgs) error {
	cni, err := wireguard.FromBytes(args.StdinData)
	if err != nil {
		return fmt.Errorf("new cni: %w", err)
	}
	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return cni.Check(args.IfName, nil)
	})
}

func Del(args *skel.CmdArgs) error {
	cni, err := wireguard.FromBytes(args.StdinData)
	if err != nil {
		return fmt.Errorf("new cni: %w", err)
	}
	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return cni.Delete(args.IfName, args.StdinData)
	})
}
