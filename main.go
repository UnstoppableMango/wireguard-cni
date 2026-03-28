//go:build linux

package main

import (
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/unstoppablemango/wireguard-cni/pkg/cmd"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	enc := zap.NewProductionEncoderConfig()
	log := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(enc),
		zapcore.Lock(os.Stderr), // stdout is reserved for CNI result
		zap.InfoLevel,
	))

	zap.ReplaceGlobals(log)
	defer log.Sync() //nolint:errcheck

	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:   cmd.Add,
			Del:   cmd.Del,
			Check: cmd.Check,
		},
		version.All,
		bv.BuildString(cmd.Name),
	)
}
