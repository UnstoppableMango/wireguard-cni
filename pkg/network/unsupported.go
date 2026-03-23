//go:build !linux

package network

func New(name string) LinkManager {
	panic("network: not supported on this platform")
}
