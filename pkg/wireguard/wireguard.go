//go:build linux

package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/network"
)

// Setup creates and configures a WireGuard interface inside the current network namespace.
// Must be called from within an ns.Do() closure.
func Setup(ifName string, conf *config.Config) error {
	la := netlink.NewLinkAttrs()
	la.Name = ifName
	link := &netlink.GenericLink{
		LinkAttrs: la,
		LinkType:  "wireguard",
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to add wireguard link %s: %v", ifName, err)
	}

	// Resolve the link after creation to get the index.
	createdLink, err := netlink.LinkByName(ifName)
	if err != nil {
		_ = netlink.LinkDel(link)
		return fmt.Errorf("failed to find created link %s: %v", ifName, err)
	}

	addr, err := network.ParseAddress(conf.Address)
	if err != nil {
		_ = netlink.LinkDel(createdLink)
		return err
	}

	if err := netlink.AddrAdd(createdLink, addr); err != nil {
		_ = netlink.LinkDel(createdLink)
		return fmt.Errorf("failed to add address %s to %s: %v", conf.Address, ifName, err)
	}

	if err := configure(ifName, conf); err != nil {
		_ = netlink.LinkDel(createdLink)
		return err
	}

	if err := netlink.LinkSetUp(createdLink); err != nil {
		_ = netlink.LinkDel(createdLink)
		return fmt.Errorf("failed to bring up %s: %v", ifName, err)
	}

	if err := network.AddPeerRoutes(createdLink, conf.Peers); err != nil {
		_ = netlink.LinkDel(createdLink)
		return err
	}

	return nil
}

// Teardown removes the WireGuard interface. Idempotent: not-found is not an error.
// Must be called from within an ns.Do() closure.
func Teardown(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("failed to find link %s: %v", ifName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete link %s: %v", ifName, err)
	}

	return nil
}

// Check verifies that the WireGuard interface exists and matches the configuration.
// Must be called from within an ns.Do() closure.
func Check(ifName string, conf *config.Config) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %v", ifName, err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list addresses on %s: %v", ifName, err)
	}

	expectedAddr, err := network.ParseAddress(conf.Address)
	if err != nil {
		return err
	}

	found := false
	for _, a := range addrs {
		if a.IPNet.String() == expectedAddr.IPNet.String() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("address %s not found on %s", conf.Address, ifName)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %v", err)
	}
	defer client.Close()

	device, err := client.Device(ifName)
	if err != nil {
		return fmt.Errorf("failed to get wireguard device %s: %v", ifName, err)
	}

	privateKey, err := ParseKey(conf.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid privateKey: %v", err)
	}

	expectedPubKey := privateKey.PublicKey()
	if device.PublicKey != expectedPubKey {
		return fmt.Errorf("wireguard public key mismatch on %s", ifName)
	}

	return nil
}

// ParseKey decodes a base64-encoded WireGuard key.
func ParseKey(b64 string) (wgtypes.Key, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to base64-decode key: %v", err)
	}
	return wgtypes.NewKey(b)
}

// configure opens a wgctrl client and applies the WireGuard configuration.
// Must be called from within an ns.Do() closure.
func configure(ifName string, conf *config.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %v", err)
	}
	defer client.Close()

	privateKey, err := ParseKey(conf.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid privateKey: %v", err)
	}

	peers, err := buildPeerConfigs(conf.Peers)
	if err != nil {
		return err
	}

	wgConf := wgtypes.Config{
		PrivateKey:   &privateKey,
		ReplacePeers: true,
		Peers:        peers,
	}
	if conf.ListenPort != 0 {
		wgConf.ListenPort = &conf.ListenPort
	}

	if err := client.ConfigureDevice(ifName, wgConf); err != nil {
		return fmt.Errorf("failed to configure wireguard device %s: %v", ifName, err)
	}

	return nil
}

// buildPeerConfigs converts config.PeerConfig slice to wgtypes.PeerConfig slice.
func buildPeerConfigs(peers []config.PeerConfig) ([]wgtypes.PeerConfig, error) {
	result := make([]wgtypes.PeerConfig, 0, len(peers))

	for i, p := range peers {
		pubKey, err := ParseKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %d: invalid publicKey: %v", i, err)
		}

		allowedIPs := make([]net.IPNet, 0, len(p.AllowedIPs))
		for _, cidr := range p.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("peer %d: invalid allowedIP %q: %v", i, cidr, err)
			}
			allowedIPs = append(allowedIPs, *ipnet)
		}

		pc := wgtypes.PeerConfig{
			PublicKey:         pubKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        allowedIPs,
		}

		if p.Endpoint != "" {
			udpAddr, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("peer %d: invalid endpoint %q: %v", i, p.Endpoint, err)
			}
			pc.Endpoint = udpAddr
		}

		if p.PersistentKeepalive > 0 {
			dur := time.Duration(p.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &dur
		}

		result = append(result, pc)
	}

	return result, nil
}
