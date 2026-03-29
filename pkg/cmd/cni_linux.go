//go:build linux

package cmd

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
)

func Add(args *skel.CmdArgs) error {
	logger(args).Info("cmdAdd")
	conf, err := config.Parse(args.StdinData)
	if err != nil {
		return err
	}
	if conf.Isolated && conf.PrevResult != nil {
		return ErrIsolated
	}

	if err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return wireguard.Add(network.New(args.IfName), conf)
	}); err != nil {
		return err
	}

	return conf.PrintResult(args)
}

func Del(args *skel.CmdArgs) error {
	logger(args).Info("cmdDel")
	if args.Netns == "" {
		return nil
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return network.New(args.IfName).Delete()
	})
}

func Check(args *skel.CmdArgs) error {
	logger(args).Info("cmdCheck")
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
