package cmd

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"go.uber.org/zap"
)

const Name = "wireguard-cni"

var (
	ErrFirstPlugin = fmt.Errorf("%s must be called as the first plugin", Name)
	ErrPrevResult  = fmt.Errorf("%s requires a prevResult", Name)
)

func logger(args *skel.CmdArgs) *zap.Logger {
	return zap.L().With(
		zap.String("interface", args.IfName),
		zap.String("netns", args.Netns),
	)
}
