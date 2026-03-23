//go:build linux

package main

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
)

const cniName = "wireguard-cni"

var (
	ErrFirstPlugin = fmt.Errorf("%s must be called as the first plugin", cniName)
	ErrPrevResult  = fmt.Errorf("%s requires a prevResult", cniName)
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
		return wireguard.Add(args.IfName, conf)
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
		return wireguard.Teardown(args.IfName)
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
	addr, wg, err := conf.Wireguard()
	if err != nil {
		return err
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return wireguard.Check(
			args.IfName,
			addr,
			wg.PrivateKey.PublicKey(),
		)
	})
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, bv.BuildString("wireguard-cni"))
}
