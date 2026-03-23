package funcs

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
)

func Add(args *skel.CmdArgs) error {
	conf, err := config.Parse(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult != nil {
		return fmt.Errorf("wireguard-cni must be called as the first plugin")
	}

	if err := config.Validate(conf); err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	if err := netns.Do(func(_ ns.NetNS) error {
		return wireguard.Setup(args.IfName, conf)
	}); err != nil {
		return err
	}

	result, err := network.BuildCNIResult(conf.CNIVersion, args.IfName, args.Netns, conf.Address)
	if err != nil {
		return err
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func Del(args *skel.CmdArgs) error {
	if args.Netns == "" {
		// Namespace already gone; nothing to do.
		return nil
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return wireguard.Teardown(args.IfName)
	})
}

func Check(args *skel.CmdArgs) error {
	conf, err := config.Parse(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("cmdCheck requires a prevResult")
	}

	if err := config.Validate(conf); err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	return netns.Do(func(_ ns.NetNS) error {
		return wireguard.Check(args.IfName, conf)
	})
}
