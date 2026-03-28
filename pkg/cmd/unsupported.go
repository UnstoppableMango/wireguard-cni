//go:build !linux

package cmd

import (
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
)

func Add(args *skel.CmdArgs) error {
	panic("unsupported platform: " + runtime.GOOS)
}

func Del(args *skel.CmdArgs) error {
	panic("unsupported platform: " + runtime.GOOS)
}

func Check(args *skel.CmdArgs) error {
	panic("unsupported platform: " + runtime.GOOS)
}
