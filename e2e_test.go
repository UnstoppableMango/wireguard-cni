package main

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/unstoppablemango/wireguard-cni/pkg/funcs"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireguardCNI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "WireGuard CNI Suite")
}

func assignAddrAndUp(ifName, cidr string) {
	GinkgoHelper()

	By("finding link " + ifName)
	link, err := netlink.LinkByName(ifName)
	Expect(err).NotTo(HaveOccurred())

	By("assigning address " + cidr)
	addr, err := netlink.ParseAddr(cidr)
	Expect(err).NotTo(HaveOccurred())
	Expect(netlink.AddrAdd(link, addr)).To(Succeed())

	By("bringing up " + ifName)
	Expect(netlink.LinkSetUp(link)).To(Succeed())
}

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

func newNetConf(privKey, peerPubKey, address string, prevResult []byte) []byte {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": privKey,
		"peers": []map[string]any{
			{
				"publicKey":  peerPubKey,
				"allowedIPs": []string{"10.0.0.0/8"},
			},
		},
	}
	if prevResult != nil {
		conf["prevResult"] = json.RawMessage(prevResult)
	}

	b, _ := json.Marshal(conf)
	return b
}

// createVethPair creates a veth pair: hostName stays in the root namespace with
// hostCIDR, peerName is moved into targetNS and assigned peerCIDR.
func createVethPair(hostName, peerName, hostCIDR, peerCIDR string, targetNS ns.NetNS) error {
	if _, _, err := ip.SetupVethWithName(hostName, peerName, 1500, "", targetNS); err != nil {
		return fmt.Errorf("create veth %s/%s: %w", hostName, peerName, err)
	}
	assignAddrAndUp(hostName, hostCIDR)

	return targetNS.Do(func(_ ns.NetNS) error {
		assignAddrAndUp(peerName, peerCIDR)
		return nil
	})
}

// setupWireGuardServer manually configures a WireGuard server in serverNS,
// mirroring wireguard.Setup but without CNI. The server listens on port 51820
// and accepts the given client public key with allowedIPs 10.99.0.0/24.
func setupWireGuardServer(serverPrivKey wgtypes.Key, clientPubKey wgtypes.Key) {
	GinkgoHelper()

	la := netlink.NewLinkAttrs()
	la.Name = "wg0"
	link := &netlink.GenericLink{
		LinkAttrs: la,
		LinkType:  "wireguard",
	}
	By("creating WireGuard interface wg0")
	Expect(netlink.LinkAdd(link)).To(Succeed())

	By("assigning address")
	assignAddrAndUp("wg0", "10.99.0.1/24")

	client, err := wgctrl.New()
	Expect(err).NotTo(HaveOccurred())
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
	Expect(client.ConfigureDevice("wg0", wgConf)).To(Succeed())
}

// addDefaultRouteInNS adds a default route inside targetNS via the given
// gateway address, using viaIface as the outbound interface.
func addDefaultRouteInNS(targetNS ns.NetNS, gateway, viaIface string) error {
	return targetNS.Do(func(ns.NetNS) error {
		link, err := netlink.LinkByName(viaIface)
		if err != nil {
			return fmt.Errorf("find iface %s: %w", viaIface, err)
		}
		return ip.AddDefaultRoute(net.ParseIP(gateway), link)
	})
}

var _ = Describe("Integration", Ordered, Label("e2e"), func() {
	var (
		testNS    ns.NetNS
		privKey   wgtypes.Key
		peerKey   wgtypes.Key
		confJSON  []byte
		addResult []byte
	)

	BeforeAll(func() {
		var err error
		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		privKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peerKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		confJSON = newNetConf(
			privKey.String(),
			peerKey.PublicKey().String(),
			"10.100.0.2/24",
			nil,
		)
	})

	AfterAll(func() {
		if testNS != nil {
			testNS.Close()
			testutils.UnmountNS(testNS)
		}
	})

	It("ADD creates the WireGuard interface with the correct address", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		var err error
		_, addResult, err = testutils.CmdAddWithArgs(args, func() error {
			return funcs.Add(args)
		})
		Expect(err).NotTo(HaveOccurred())

		err = testNS.Do(func(_ ns.NetNS) error {
			link, lerr := netlink.LinkByName("wg0")
			if lerr != nil {
				return lerr
			}

			addrs, lerr := netlink.AddrList(link, netlink.FAMILY_ALL)
			if lerr != nil {
				return lerr
			}

			found := false
			for _, a := range addrs {
				if a.IP.String() == "10.100.0.2" {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("address 10.100.0.2 not found on wg0")
			}

			client, lerr := wgctrl.New()
			if lerr != nil {
				return lerr
			}
			defer client.Close()

			dev, lerr := client.Device("wg0")
			if lerr != nil {
				return lerr
			}

			expectedPub := privKey.PublicKey()
			if dev.PublicKey != expectedPub {
				return fmt.Errorf("public key mismatch")
			}

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("CHECK succeeds after ADD", func() {
		checkConf := newNetConf(
			privKey.String(),
			peerKey.PublicKey().String(),
			"10.100.0.2/24",
			addResult,
		)
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   checkConf,
		}

		err := testutils.CmdCheckWithArgs(args, func() error {
			return funcs.Check(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("CHECK fails without prevResult", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		err := funcs.Check(args)
		Expect(err).To(MatchError(ContainSubstring("requires a prevResult")))
	})

	It("DEL removes the interface", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		err := testutils.CmdDelWithArgs(args, func() error {
			return funcs.Del(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("DEL is idempotent (second call succeeds)", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		err := testutils.CmdDelWithArgs(args, func() error {
			return funcs.Del(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})
})

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

		Expect(ip.EnableIP4Forward()).To(Succeed())

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

		Expect(serverNS.Do(func(ns.NetNS) error {
			setupWireGuardServer(serverPrivKey, clientPrivKey.PublicKey())
			return nil
		})).To(Succeed())

		confJSON = newE2ENetConf(
			clientPrivKey.String(),
			serverPrivKey.PublicKey().String(),
			"10.99.0.2/24",
			"10.200.0.2:51820",
		)
	})

	AfterAll(func() {
		if clientNS != nil {
			clientNS.Close()
			testutils.UnmountNS(clientNS)
		}
		if serverNS != nil {
			serverNS.Close()
			testutils.UnmountNS(serverNS)
		}

		// Clean up host-side veth ends (peer sides are removed with their namespaces).
		for _, ifName := range []string{"veth0-srv", "veth0-cli"} {
			ip.DelLinkByName(ifName)
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
			return funcs.Add(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("client can reach server through WireGuard tunnel", func() {
		addr := "10.99.0.1:19999"

		var ln net.Listener
		Expect(serverNS.Do(func(ns.NetNS) error {
			var err error
			ln, err = net.Listen("tcp4", addr)
			return err
		})).NotTo(HaveOccurred())
		DeferCleanup(ln.Close)

		By("waiting for server to be ready")
		accepted := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				conn.Close()
			}
			accepted <- err
		}()

		By("dialing server from client")
		Expect(clientNS.Do(func(ns.NetNS) error {
			conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
			if err != nil {
				return err
			}
			conn.Close()
			return nil
		})).NotTo(HaveOccurred())
		Expect(<-accepted).NotTo(HaveOccurred())
	})
})
