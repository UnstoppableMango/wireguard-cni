package main

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult != nil {
		return fmt.Errorf("must be called as the first plugin")
	}

	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}
	result.Interfaces = []*current.Interface{
		{
			Name:    "intf0",
			Sandbox: args.Netns,
			Mac:     "00:11:22:33:44:55",
		},
	}
	result.IPs = []*current.IPConfig{
		{
			// Address: "1.2.3.4/24",
			// Gateway: "1.2.3.1",
			// Interface is an index into the Interfaces array
			// of the Interface element this IP applies to
			Interface: current.Int(0),
		},
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add: cmdAdd,
	}, version.All, bv.BuildString("wireguard"))
}
