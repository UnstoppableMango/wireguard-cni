//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const pluginName = "wireguard-cni"

var (
	ErrFirstPlugin = fmt.Errorf("%s must be called as the first plugin", pluginName)
	ErrPrevResult  = fmt.Errorf("%s requires a prevResult", pluginName)
)

func withArgs(args *skel.CmdArgs) *zap.Logger {
	return zap.L().With(
		zap.String("interface", args.IfName),
		zap.String("netns", args.Netns),
	)
}

func cmdAdd(args *skel.CmdArgs) error {
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

func cmdDel(args *skel.CmdArgs) error {
	withArgs(args).Info("cmdDel")
	if args.Netns == "" {
		return nil
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		return network.New(args.IfName).Delete()
	})
}

func cmdCheck(args *skel.CmdArgs) error {
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

func main() {
	enc := zap.NewProductionEncoderConfig()
	log := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(enc),
		zapcore.Lock(os.Stderr), // stdout is reserved for CNI result
		zap.InfoLevel,
	))

	zap.ReplaceGlobals(log)
	defer log.Sync() //nolint:errcheck

	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   cmdAdd,
		Del:   cmdDel,
		Check: cmdCheck,
	}, version.All, bv.BuildString(pluginName))
}
