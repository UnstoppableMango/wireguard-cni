//go:build linux

package main

import (
	"fmt"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

func init() {
	// Ensure all netlink and wgctrl calls happen on a thread that can be
	// locked to a specific OS-level network namespace.
	runtime.LockOSThread()
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult != nil {
		return fmt.Errorf("wireguard-cni must be called as the first plugin")
	}

	if err := validateConfig(conf); err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	if err := netns.Do(func(_ ns.NetNS) error {
		return setupWireGuard(args.IfName, conf)
	}); err != nil {
		return err
	}

	result, err := buildCNIResult(conf.CNIVersion, args.IfName, args.Netns, conf.Address)
	if err != nil {
		return err
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	if args.Netns == "" {
		// Namespace already gone; nothing to do.
		return nil
	}

	return ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		return teardownWireGuard(args.IfName)
	})
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("cmdCheck requires a prevResult")
	}

	if err := validateConfig(conf); err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	return netns.Do(func(_ ns.NetNS) error {
		return checkWireGuard(args.IfName, conf)
	})
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, bv.BuildString("wireguard-cni"))
}
