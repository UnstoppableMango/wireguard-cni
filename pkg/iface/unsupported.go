//go:build !linux

package iface

import (
	"fmt"
	"runtime"
)

func Create(ifName string) (Link, error) {
	return nil, fmt.Errorf("platform not supported: %s", runtime.GOOS)
}

func HandleAt(string) (NS, error) {
	return nil, fmt.Errorf("platform not supported: %s", runtime.GOOS)
}
