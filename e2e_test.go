//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newE2ENetConf(privKey, peerPubKey, address, endpoint string) []byte {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-e2e",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": privKey,
		"peers": []map[string]any{
			{
				"publicKey":           peerPubKey,
				"allowedIPs":          []string{"10.99.0.1/32"},
				"endpoint":            endpoint,
				"persistentKeepalive": 5,
			},
		},
	}
	b, _ := json.Marshal(conf)
	return b
}

// createVethPair creates a veth pair in the root namespace, assigns hostCIDR to
// the host-side interface, moves the peer into targetNS, and assigns peerCIDR
// inside that namespace. Both interfaces are brought up.
func createVethPair(hostName, peerName, hostCIDR, peerCIDR string, targetNS ns.NetNS) error {
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: hostName},
		PeerName:  peerName,
	}); err != nil {
		return fmt.Errorf("create veth %s/%s: %w", hostName, peerName, err)
	}

	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("find host veth %s: %w", hostName, err)
	}

	hostAddr, err := netlink.ParseAddr(hostCIDR)
	if err != nil {
		return fmt.Errorf("parse host addr %s: %w", hostCIDR, err)
	}
	if err := netlink.AddrAdd(hostLink, hostAddr); err != nil {
		return fmt.Errorf("add addr to %s: %w", hostName, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("bring up %s: %w", hostName, err)
	}

	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		return fmt.Errorf("find peer veth %s: %w", peerName, err)
	}
	if err := netlink.LinkSetNsFd(peerLink, int(targetNS.Fd())); err != nil {
		return fmt.Errorf("move %s to ns: %w", peerName, err)
	}

	return targetNS.Do(func(_ ns.NetNS) error {
		peer, err := netlink.LinkByName(peerName)
		if err != nil {
			return fmt.Errorf("find %s in ns: %w", peerName, err)
		}
		addr, err := netlink.ParseAddr(peerCIDR)
		if err != nil {
			return fmt.Errorf("parse peer addr %s: %w", peerCIDR, err)
		}
		if err := netlink.AddrAdd(peer, addr); err != nil {
			return fmt.Errorf("add addr to %s: %w", peerName, err)
		}
		return netlink.LinkSetUp(peer)
	})
}

func enableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

// setupWireGuardServer manually configures a WireGuard server in serverNS,
// mirroring wireguard.Setup but without CNI. The server listens on port 51820
// and accepts the given client public key with allowedIPs 10.99.0.0/24.
func setupWireGuardServer(serverNS ns.NetNS, serverPrivKey wgtypes.Key, clientPubKey wgtypes.Key) error {
	return serverNS.Do(func(_ ns.NetNS) error {
		la := netlink.NewLinkAttrs()
		la.Name = "wg0"
		link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}
		if err := netlink.LinkAdd(link); err != nil {
			return fmt.Errorf("add server wg0: %w", err)
		}

		wgLink, err := netlink.LinkByName("wg0")
		if err != nil {
			return err
		}

		addr, err := netlink.ParseAddr("10.99.0.1/24")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(wgLink, addr); err != nil {
			return fmt.Errorf("add addr to server wg0: %w", err)
		}

		client, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("wgctrl.New: %w", err)
		}
		defer client.Close()

		listenPort := 51820
		_, allowedNet, _ := net.ParseCIDR("10.99.0.0/24")
		wgConf := wgtypes.Config{
			PrivateKey:   &serverPrivKey,
			ListenPort:   &listenPort,
			ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:         clientPubKey,
					ReplaceAllowedIPs: true,
					AllowedIPs:        []net.IPNet{*allowedNet},
				},
			},
		}
		if err := client.ConfigureDevice("wg0", wgConf); err != nil {
			return fmt.Errorf("configure server wg0: %w", err)
		}

		return netlink.LinkSetUp(wgLink)
	})
}

// addDefaultRouteInNS adds a default route inside targetNS via the given
// gateway address, using viaIface as the outbound interface.
func addDefaultRouteInNS(targetNS ns.NetNS, gateway, viaIface string) error {
	return targetNS.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(viaIface)
		if err != nil {
			return fmt.Errorf("find iface %s: %w", viaIface, err)
		}
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        net.ParseIP(gateway),
		})
	})
}

// checkTunnelConnectivity verifies end-to-end connectivity through the WireGuard
// tunnel by opening a TCP listener in serverNS and dialing it from clientNS.
func checkTunnelConnectivity(serverNS, clientNS ns.NetNS, serverTunnelIP string) error {
	const port = 19999
	addr := fmt.Sprintf("%s:%d", serverTunnelIP, port)

	var ln net.Listener
	if err := serverNS.Do(func(_ ns.NetNS) error {
		var err error
		ln, err = net.Listen("tcp4", addr)
		return err
	}); err != nil {
		return fmt.Errorf("listen in serverNS: %w", err)
	}
	defer ln.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err
	}()

	if err := clientNS.Do(func(_ ns.NetNS) error {
		conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}); err != nil {
		return fmt.Errorf("dial from clientNS: %w", err)
	}

	return <-accepted
}

var _ = Describe("E2E", Ordered, Label("e2e"), func() {
	var (
		serverNS      ns.NetNS
		clientNS      ns.NetNS
		serverPrivKey wgtypes.Key
		clientPrivKey wgtypes.Key
		confJSON      []byte
	)

	BeforeAll(func() {
		var err error

		serverNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		clientNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		serverPrivKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		clientPrivKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		Expect(enableIPForwarding()).To(Succeed())

		Expect(createVethPair(
			"veth0-srv", "veth1-srv",
			"10.200.0.1/30", "10.200.0.2/30",
			serverNS,
		)).To(Succeed())

		Expect(createVethPair(
			"veth0-cli", "veth1-cli",
			"10.200.1.1/30", "10.200.1.2/30",
			clientNS,
		)).To(Succeed())

		// Client needs a route to reach 10.200.0.2 (server veth) for the WireGuard handshake.
		Expect(addDefaultRouteInNS(clientNS, "10.200.1.1", "veth1-cli")).To(Succeed())
		// Server needs a route back to 10.200.1.x (client veth) to reply to WireGuard packets.
		Expect(addDefaultRouteInNS(serverNS, "10.200.0.1", "veth1-srv")).To(Succeed())

		Expect(setupWireGuardServer(serverNS, serverPrivKey, clientPrivKey.PublicKey())).To(Succeed())

		confJSON = newE2ENetConf(
			keyBase64(clientPrivKey),
			keyBase64(serverPrivKey.PublicKey()),
			"10.99.0.2/24",
			"10.200.0.2:51820",
		)
	})

	AfterAll(func() {
		if clientNS != nil {
			args := &skel.CmdArgs{
				ContainerID: "e2e-client",
				Netns:       clientNS.Path(),
				IfName:      "wg0",
				StdinData:   confJSON,
			}
			_ = testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
			clientNS.Close()
			testutils.UnmountNS(clientNS)
		}

		if serverNS != nil {
			serverNS.Close()
			testutils.UnmountNS(serverNS)
		}

		// Clean up host-side veth ends (peer sides are removed with their namespaces).
		for _, ifName := range []string{"veth0-srv", "veth0-cli"} {
			if link, err := netlink.LinkByName(ifName); err == nil {
				_ = netlink.LinkDel(link)
			}
		}
	})

	It("CNI ADD configures the client WireGuard interface", func() {
		args := &skel.CmdArgs{
			ContainerID: "e2e-client",
			Netns:       clientNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		_, _, err := testutils.CmdAddWithArgs(args, func() error {
			return cmdAdd(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("client can reach server through WireGuard tunnel", func() {
		Expect(checkTunnelConnectivity(serverNS, clientNS, "10.99.0.1")).To(Succeed())
	})
})
