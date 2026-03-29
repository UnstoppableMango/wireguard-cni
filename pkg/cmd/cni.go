package cmd

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"go.uber.org/zap"
)

const Name = "wireguard-cni"

var (
	ErrIsolated   = fmt.Errorf("%s: isolated mode does not accept a prevResult", Name)
	ErrPrevResult = fmt.Errorf("%s requires a prevResult", Name)
)

func logger(args *skel.CmdArgs) *zap.Logger {
	return zap.L().With(
		zap.String("interface", args.IfName),
		zap.String("netns", args.Netns),
	)
}
