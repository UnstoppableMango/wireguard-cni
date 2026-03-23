package wireguard

import (
	"fmt"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
)

func Add(ifName string, conf *config.Config) error {
	if addr, wg, err := conf.Wireguard(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	} else {
		return Name(ifName).Add(addr, wg)
	}
}

// Teardown removes the WireGuard interface. Idempotent: not-found is not an error.
// Must be called from within an ns.Do() closure.
func Teardown(ifName string) error {
	return Name(ifName).Teardown()
}

// Check verifies that the WireGuard interface exists, has the configured address,
// and that the device public key matches the configured private key.
// Must be called from within an ns.Do() closure.
func Check(ifName string, conf *config.Config) error {
	if addr, wg, err := conf.Wireguard(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	} else {
		return Name(ifName).Check(addr, wg.PrivateKey.PublicKey())
	}
}
