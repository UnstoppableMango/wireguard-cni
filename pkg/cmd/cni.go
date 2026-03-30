package cmd

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"go.uber.org/zap"
)

const Name = "wireguard-cni"

var (
	ErrPrevResult     = fmt.Errorf("%s: CHECK requires a prevResult from a prior ADD", Name)
	ErrChainedVersion = fmt.Errorf("%s: chained mode requires CNI spec >= 0.3.0", Name)
)

func logger(args *skel.CmdArgs) *zap.Logger {
	return zap.L().With(
		zap.String("interface", args.IfName),
		zap.String("netns", args.Netns),
	)
}
