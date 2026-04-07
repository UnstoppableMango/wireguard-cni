//go:build !linux

package iface

import (
	"fmt"
	"runtime"
)

var errUnsupported = fmt.Errorf("platform not supported: %s", runtime.GOOS)

func Create(ifName string) (Link, error) {
	panic(errUnsupported)
}

func HandleAt(string) (NS, error) {
	panic(errUnsupported)
}

func NewClient() Client {
	panic(errUnsupported)
}
