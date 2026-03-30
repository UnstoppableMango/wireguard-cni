package wireguard_test

import (
	"fmt"
	"net"

	"github.com/unstoppablemango/wireguard-cni/pkg/network"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// notFoundError returns network.ErrLinkNotFound so that network.IsNotFound returns true.
func notFoundError() error {
	return network.ErrLinkNotFound
}

// fakeLink implements network.Link and records calls.
type fakeLink struct {
	assignAddressErr      error
	configureWireguardErr error
	bringUpErr            error
	addRouteErr           error
	addressesErr          error
	addresses             []*net.IPNet
	publicKeyErr          error
	publicKey             wgtypes.Key

	assignedAddr   *net.IPNet
	configuredConf *wgtypes.Config
	addedRoutes    []*net.IPNet
	assignCalled   bool
}

func (f *fakeLink) AssignAddress(addr *net.IPNet) error {
	f.assignCalled = true
	f.assignedAddr = addr
	return f.assignAddressErr
}

func (f *fakeLink) ConfigureWireGuard(conf wgtypes.Config) error {
	f.configuredConf = &conf
	return f.configureWireguardErr
}

func (f *fakeLink) BringUp() error {
	return f.bringUpErr
}

func (f *fakeLink) AddRoute(dst *net.IPNet) error {
	f.addedRoutes = append(f.addedRoutes, dst)
	return f.addRouteErr
}

func (f *fakeLink) Addresses() ([]*net.IPNet, error) {
	return f.addresses, f.addressesErr
}

func (f *fakeLink) PublicKey() (wgtypes.Key, error) {
	return f.publicKey, f.publicKeyErr
}

func (f *fakeLink) String() string {
	return fmt.Sprintf("fake(%s)", f.assignedAddr.IP)
}

// fakeLinkManager implements network.LinkManager.
type fakeLinkManager struct {
	createLink network.Link
	createErr  error
	deleteErr  error
	getLink    network.Link
	getErr     error
	deleted    bool
	created    bool
}

func (f *fakeLinkManager) Create() (network.Link, error) {
	f.created = true
	return f.createLink, f.createErr
}

func (f *fakeLinkManager) Delete() error {
	f.deleted = true
	return f.deleteErr
}

func (f *fakeLinkManager) Get() (network.Link, error) {
	return f.getLink, f.getErr
}
