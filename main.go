//go:build linux

package main

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
)

const pluginName = "wireguard-cni"

var (
	ErrFirstPlugin = fmt.Errorf("%s must be called as the first plugin", pluginName)
	ErrPrevResult  = fmt.Errorf("%s requires a prevResult", pluginName)
)

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := config.Parse(args.StdinData)
	if err != nil {
		return err
	}
	if conf.PrevResult != nil {
		return ErrFirstPlugin
	}

	if err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return wireguard.Add(network.New(args.IfName), conf)
	}); err != nil {
		return err
	}

	return conf.PrintResult(args)
}

func cmdDel(args *skel.CmdArgs) error {
	if args.Netns == "" {
		return nil
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return network.New(args.IfName).Delete()
	})
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, err := config.Parse(args.StdinData)
	if err != nil {
		return err
	}
	if conf.PrevResult == nil {
		return ErrPrevResult
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return wireguard.Check(network.New(args.IfName), conf)
	})
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, bv.BuildString(pluginName))
}
