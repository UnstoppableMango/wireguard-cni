package network

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Link is a handle to a network interface. Methods correspond to the
// operations the CNI plugin performs when configuring an interface.
type Link interface {
	// AssignAddress assigns the given CIDR address to the link.
	AssignAddress(addr *net.IPNet) error
	// BringUp activates the link.
	BringUp() error
	// AddRoute installs a route for dst via this link.
	AddRoute(dst *net.IPNet) error
	// Addresses returns all IP addresses currently assigned to this link.
	Addresses() ([]*net.IPNet, error)
	// ConfigureWireGuard applies keys, peers, and listen port to the WireGuard device.
	ConfigureWireGuard(conf wgtypes.Config) error
	// PublicKey returns the public key currently set on the WireGuard device.
	PublicKey() (wgtypes.Key, error)
}

// LinkManager manages a single named network link. The link name is
// embedded in the implementation rather than passed per-call.
type LinkManager interface {
	// Create creates a new WireGuard link and returns a handle for
	// further configuration.
	Create() (Link, error)
	// Delete removes the link. Idempotent: returns nil if not found.
	Delete() error
	// Get returns a handle to the existing link.
	Get() (Link, error)
}
