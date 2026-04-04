//go:build linux

package cmd

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
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

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as a chained plugin")
	}

	defer func() {
		if err != nil {
			_ = conf.IPAMDel(args.StdinData)
		}
	}()

	var ipam *current.Result
	logger(args).Info("invoking ipam add")
	if ipam, err = conf.IPAMAdd(args.StdinData); err != nil {
		return err
	}
	logger(args).Info("configuring interface")
	if err := wireguard.ConfigureAll(ipam.IPs); err != nil {
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

	prev, err := current.GetResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("get prevResult: %w", err)
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return wireguard.Check(network.New(args.IfName), conf, args.IfName, prev)
	})
}
