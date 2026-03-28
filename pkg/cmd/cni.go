//go:build linux

package cmd

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
	"go.uber.org/zap"
)

const Name = "wireguard-cni"

var (
	ErrFirstPlugin = fmt.Errorf("%s must be called as the first plugin", Name)
	ErrPrevResult  = fmt.Errorf("%s requires a prevResult", Name)
)

func withArgs(args *skel.CmdArgs) *zap.Logger {
	return zap.L().With(
		zap.String("interface", args.IfName),
		zap.String("netns", args.Netns),
	)
}

func Add(args *skel.CmdArgs) error {
	withArgs(args).Info("cmdAdd")
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

func Del(args *skel.CmdArgs) error {
	withArgs(args).Info("cmdDel")
	if args.Netns == "" {
		return nil
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return network.New(args.IfName).Delete()
	})
}

func Check(args *skel.CmdArgs) error {
	withArgs(args).Info("cmdCheck")
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
